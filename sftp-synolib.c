#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
// Copyright (c) 2000-2014 Synology Inc. All rights reserved.
#include "sftp-synolib.h"
#include "sftp.h"
#include "xmalloc.h"

#include <fcntl.h>
#include <signal.h>
#include <libgen.h>
#include <unistd.h>
#include <stdarg.h>

#include <synologd/synolog.h>
#include <synocore/conf.h>
#include <synofileop/ea.h>
#include <synocore/file.h>
#include <synoftp.h>
#include <synossh.h>
#include <synosdk/log.h>
#include <synocurconn/curconn.h>
#include <synocore/proc.h>
#include <synosdk/service.h>
#include <synocore/string.h>
#include <synosdk/appprivilege.h>

#ifdef MY_ABC_HERE
#include <synorecycle/synorecycle.h>
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE

#ifdef MY_ABC_HERE
void SYNOSftpXferSysLog(const char *szIP, const char *szUser, const char *fmt, ...)
{
	char szFmt[1024] = "";
	char szLog[PATH_MAX * 2 + 64] = "";
	va_list args;

	if (NULL == szIP || NULL == szUser) {
		syslog(LOG_ERR, "Failed to SYNOSftpXferSysLog()");
		return;
	}

	va_start(args, fmt);

	snprintf(szFmt, sizeof(szFmt), "[%s, %s] - %s", szIP, szUser, fmt);
	vsnprintf(szLog, sizeof(szLog), szFmt, args);
	syslog(LOG_DEBUG, "%s", szLog);

	va_end(args);
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int SYNOLogFTPXferLogEx(const char *pszIP, SYNOSftpSessionConfig *pConf, const char *pszCmd, off_t size, const char *pszPath, int blIsDir)
{
	char szPath[PATH_MAX] = "";
	if (IS_CHROOT(&pConf->user)) {
		snprintf(szPath, sizeof(szPath), "/%s%s", pConf->user.chroot.szHomeShare, pszPath);
	} else {
		snprintf(szPath, sizeof(szPath), "%s", pszPath);
	}
	return SYNOLogFTPXferLog(pszIP, pConf->user.szName, pszCmd, size, szPath, blIsDir, 0);
}
#endif /* MY_ABC_HERE */

static int BecomeRoot()
{
	int err = -1;

	if (UID_ROOT != geteuid()) {
		if (0 > seteuid(UID_ROOT)){
			SYSLOG(LOG_ERR, "failed to set euid to root, errno=%m");
			goto Err;
		}
	}

	err = 0;
Err:
	return err;
}

static int UnBecomeRoot(const SYNOSftpUserInfo *pUser)
{
	if (!IS_ADMIN(pUser)) {
		if (0 > seteuid(pUser->uid)){
			SYSLOG(LOG_ERR, "failed to set euid to user [%u], errno=%m", pUser->uid);
			return -1;
		}
	}
	return 0;
}

static SYNOSftpShareInfo * FindShare(SYNOSftpValidShares *pShares, const SYNOSftpUserInfo *pUser, const char *szShareName)
{
	SYNOSftpShareHash *pFound = NULL;

	if (!pShares->pHash) {
		SYSLOG(LOG_ERR, "no hash exist, and failed to enum share into memory");
		return NULL;
	}

	HASH_FIND_STR(pShares->pHash, szShareName, pFound);

	if (!pFound) {
		SYSLOG(LOG_ERR, "not found share [%s]", szShareName);
		return NULL;
	}

	return pFound->pShare;
}

static char * GetShareRealPath(SYNOSftpValidShares *pShares, const SYNOSftpUserInfo *pUser, char *szPath, SYNOSftpShareInfo ** ppShare)
{
	char *ptr = NULL;
	char *szRealPath = NULL;
	char *szShareName = NULL;	
	SYNOSftpShareInfo * pShare = NULL;

	if (!pUser || !szPath) {
		SYSLOG(LOG_ERR, "path or user can NOT be NULL (%s)", __FUNCTION__);
		return NULL;
	}

	//Parse share name
	szShareName = szPath + 1;
	if (NULL != (ptr = strchr(szShareName, '/'))) {
		*ptr = '\0';
	}
	//Get share real path
	
	if (NULL == (pShare = FindShare(pShares, pUser, szShareName))) {
		goto Err;
	}

	if (ptr) {// folders under share path
		int len = strlen(pShare->path) + strlen(ptr + 1) + 2; // '/' and '\0'
		if (NULL == (szRealPath = (char *)xmalloc(len))){
			goto Err;
		}
		snprintf(szRealPath, len, "%s/%s", pShare->path, ptr+1);
	} else {// share path
		if (NULL == (szRealPath = xstrdup(pShare->path))){
			goto Err;
		}
	}
	
	if (ppShare) {
		*ppShare = pShare;
	}
Err:
	if (ptr) { //restore '/'
		*ptr = '/';
	}
	return szRealPath;
}

#ifdef MY_ABC_HERE
static char * GetChrootRealPath(const char *szPath)
{
	int len = 0;
	char *szRealPath = NULL;

	if (!szPath) {
		SYSLOG(LOG_ERR, "path can not be NULL");
		return NULL;
	}

	len = strlen(szPath) + 3; // '.', '/', '\0'
	if (NULL == (szRealPath = xmalloc(len))){
		SYSLOG(LOG_ERR, "failed to xmalloc for [%s], errno=%m", szPath);
		return NULL;
	}

	snprintf(szRealPath, len, "./%s", szPath);

	return szRealPath;
}
#endif /* MY_ABC_HERE */

static SYNO_PATH_TYPE GetPathType(const char *szAbsPath, BOOL blChroot)
{
	if (!blChroot) {
		if (IS_ROOT_PATH(szAbsPath)) {
			return SFTP_PATH_ROOT;
		}
		if (IS_SHARE_PATH(szAbsPath)) {
			return SFTP_PATH_SHARE;
		}
	}
	return SFTP_PATH_SUBFOLDER;
}

static int GetUserPrivOnShare(const SYNOSftpUserInfo *pUser, const PSYNOSHARE pShare, int *pPriv)
{
	int err = -1;
	const char *szUserName = NULL;

	if (!pUser || !pShare || !pPriv) {
		SYSLOG(LOG_ERR, "Bad parameter");
		goto Err;
	}

	szUserName = pUser->szName;

	*pPriv = SYNOShareUserPrivGet(szUserName, pShare);

	err = 0;
Err:
	return err;
}

/**
 * Get real path from virtual path.<p>
 * For example:
 * Chroot:
 *    - '/'  ==> "./"
 *    - '/public'  ==> "./public"<p>
 * No Chroot:
 *    - '/'  ==> "/"
 *    - '/public'  ==> "/volume1/public"
 * 
 * @param pShares [IN] shares list
 * @param pUser   [IN] user information
 * @param szPath  [IN] virtual path
 * @param ppPerm  [OUT] user permission on path, NO need to free.
 * 
 * @return Not NULL: real path
 *         NULL: err
 */
static char *GetPathInfo(SYNOSftpValidShares *pShares, SYNOSftpUserInfo *pUser, char *szPath, SYNOSftpPathInfo *pPathInfo)
{
	int err = -1;
	int iPriv;
	char *szRealPath = NULL;
	char *szAbsPath = NULL;
	PSYNOSHARE pSynoShare = NULL;

	if (!pShares || !pUser || !szPath || 0 == strlen(szPath)) {
		return NULL;
	}

	// Remove '.' and ".." of path
	if (NULL == (szAbsPath = SYNOSftpPathRemoveDot(szPath))){
		goto Err;
	}

#ifdef MY_ABC_HERE
	if (IS_CHROOT(pUser)) {
		if (NULL == (szRealPath = GetChrootRealPath(szAbsPath))){
			goto Err;
		}
		pPathInfo->pPerm = &(pUser->chroot.perm);
		pPathInfo->pathType = GetPathType(szAbsPath, TRUE);
		err = 0;
		goto Err;
	}
#endif /* MY_ABC_HERE */

	SYNOSftpShareInfo *pShare = NULL;

	pPathInfo->pathType = GetPathType(szAbsPath, FALSE);
	if (SFTP_PATH_ROOT != pPathInfo->pathType) {
		if (NULL == (szRealPath = GetShareRealPath(pShares, pUser, szAbsPath, &pShare))){
			goto Err;
		}
		if (pShare) {
			if (0 != strcmp(pShare->perm.szShareName, "home")) {
				if (NULL == pShare->perm.szShareName || 0 > SYNOShareGet(pShare->perm.szShareName, &pSynoShare)){
					SYSLOG(LOG_ERR, "failed to get share [%s]. "SLIBERR_FMT, pShare->perm.szShareName, SLIBERR_ARGS);
					goto Err;
				}
				if (0 > GetUserPrivOnShare(pUser, pSynoShare, &iPriv)){
					SYSLOG(LOG_ERR, "failed to get share [%s] privilege for user [%s]. "SLIBERR_FMT, pUser->szName, pSynoShare->szName, SLIBERR_ARGS);
					goto Err;
				}
				pShare->perm.sharePriv = iPriv;
			}
			pPathInfo->pPerm = &(pShare->perm);
		}
	} else {
		szRealPath = xstrdup(szAbsPath);
	}

	err = 0;
Err:
	free(szAbsPath);
	if (err) {
		if (szRealPath) {
			free(szRealPath);
			szRealPath = NULL;
		}
	}
	SYNOShareFree(pSynoShare);
	return szRealPath;
}


#ifdef MY_ABC_HERE
static void LogLogin(const unsigned long eventId, const char *szUser, const uid_t uid, const char *szIP)
{
	char szUID[16] = {0};

	snprintf(szUID, sizeof(szUID), "%u", uid);
	SLIBLogSet("auth", eventId, szUser, szUID, szIP, "SFTP");
}

#define UNIT_GB (1 << 30)
#define UNIT_MB (1 << 20)
#define UNIT_KB (1 << 10)

static void UnitTransfer(off_t size, char *szSize, int cbSize)
{
	if (size > UNIT_GB) {
		snprintf(szSize, cbSize, "%12.2f GB", (double)size / UNIT_GB);
	} else if (size > UNIT_MB) {
		snprintf(szSize, cbSize, "%6.2f MB", (double)size / UNIT_MB);
	} else if (size > UNIT_KB) {
		snprintf(szSize, cbSize, "%6.2f KB", (double)size / UNIT_KB);
	} else {
		snprintf(szSize, cbSize, "%lld Bytes", (long long)size);
	}
}

static void LogLogout(const char *szUser, const uid_t uid, const char *szIP, off_t writeBytes, off_t readBytes)
{
	char szUpload[64], szDownload[64];
	char szUID[16] = {0};

	UnitTransfer(writeBytes, szUpload, sizeof(szUpload));
	UnitTransfer(readBytes, szDownload, sizeof(szDownload));
	snprintf(szUID, sizeof(szUID), "%u", uid);

	SLIBLogSet("auth", LOG_LOGOUT_SUCCESS, szUser, szUID, szIP, "SFTP", szUpload, szDownload);
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int UpdateCurrConnLog(char *szShareName, SYNOSftpSessionConfig *pConf, const char *szIP)
{
	int ret = -1;
	int err = -1;
	int cbSize = 0; 
	char *szLine = NULL;
	char *szUserName = NULL;
	char szKey[32];
	SYNOSftpUserInfo *pUser = &pConf->user;

	BecomeRoot();

	cbSize = strlen(pUser->szName) + strlen(szIP) + 64;
	if (NULL == (szLine = malloc(cbSize))){
		SYSLOG(LOG_ERR, "failed to malloc, errno=%m");
		goto Err;
	}
	if (IS_ANONYMOUS(pUser)) {
		szUserName = SYNO_ANONYMOUSE_DISPLAYNAME;
	} else {
		szUserName = pUser->szName;
	}

	if (0 > SLIBCFileLock(LOCK_SFTP_CURRLOG | LOCK_EX_NB, LOCK_TIMEOUT)) {
		SYSLOG(LOG_ERR, "failed to lock sftp currlog. "SLIBERR_FMT, SLIBERR_ARGS);
		goto Err;
	}

	if (!CWD_SHARE(pConf) || !IS_STR_EQUAL(szShareName, CWD_SHARE(pConf))) {
		StrfCP(szKey, "%u", getpid());
		snprintf(szLine, cbSize, "%s\t%ld\t%s\t%s\t%s", szKey, time(NULL), szUserName, szIP, szShareName?szShareName:"");

		if (0 > (ret = SLIBCFileSetLine(SZF_SFTPD_CONNECTION_REC, szKey, szLine, OP_FIND_PREFIX))){
			SYSLOG(LOG_ERR, "failed to set line[%s]. "SLIBERR_FMT, szLine, SLIBERR_ARGS);
			goto Err;
		}
		if (0 == ret) {
			if (0 > SLIBCFileAddLine(SZF_SFTPD_CONNECTION_REC, NULL, szLine, OP_ADD_AFTER)){
				SYSLOG(LOG_ERR, "failed to add line into [%s]. "SLIBERR_FMT, SZF_SFTPD_CONNECTION_REC, SLIBERR_ARGS);
				goto Err;			
			}
		}
		CWD_SHARE(pConf) = szShareName;
	}

	err = 0;
Err:
	SLIBCFileUnlock(LOCK_SFTP_CURRLOG);
	UnBecomeRoot(pUser);

	return err;
}
#endif /* MY_ABC_HERE */

#include <libgen.h>

static void FreeSftpShare(SYNOSftpShareInfo *pShare)
{
	if (!pShare) {
		return;
	}

	if (pShare->share) {
		free(pShare->share);
	}
	if (pShare->path) {
		free(pShare->path);
	}
}

static void	AppendSftpShare(SYNOSftpShareInfo **ppList, SYNOSftpShareInfo *pShare)
{
	SYNOSftpShareInfo *pEnd = NULL;

	if (!ppList || !pShare) {
		return;
	}

	if (NULL == *ppList) {
		*ppList = pShare;
		return;
	}

	for (pEnd = *ppList; pEnd->next; pEnd = pEnd->next) {;}
	pEnd->next = pShare;
}

static void FreeValidShares(SYNOSftpValidShares *pShares)
{
	SYNOSftpShareInfo * pFreeShare, *pShare = NULL;
	SYNOSftpShareHash * pshTmp, *pshShare;

	if (!pShares) {
		return;
	}

	//Free Hash
	HASH_ITER(hh, pShares->pHash, pshShare, pshTmp) {
		HASH_DEL(pShares->pHash, pshShare);
	}

	//Free Shares
	pShare = pShares->pShare;
	while (pShare) {
		pFreeShare = pShare;
		pShare = pShare->next;
		FreeSftpShare(pFreeShare);
	}

	bzero(pShares, sizeof(*pShares));
}

static void MapToSftpPerm(int isAdmin, int ftpPriv, int sharePriv, SYNOSftpPerm *pPerm)
{
	if (ftpPriv && 1 != isAdmin) {
		if (ftpPriv & FTP_PRIV_DISABLE_LIST) {
			pPerm->disable_ls = 1;
		}
		if (ftpPriv & FTP_PRIV_DISABLE_MODIFY) {
			pPerm->disable_modifify = 1;
		}
		if (ftpPriv & FTP_PRIV_DISABLE_DOWNLOAD) {
			pPerm->disable_download = 1;
		}
	}
	pPerm->sharePriv = sharePriv;
}

static void AppendShares(SYNOSftpValidShares *pShares, const SYNOSftpUserInfo *pUser, PSYNOSHARE pShare, int iPriv, BOOL blOnlyACL)
{
	int err = -1;
	SYNOSftpShareInfo *pSftpShare = NULL;
	SYNOSftpShareHash *pHashShare = NULL;

	if (!pShare || !pUser) {
		return;
	}

	//Prepare SFTP Share.
	if (NULL == (pSftpShare = (SYNOSftpShareInfo *)calloc(1, sizeof(SYNOSftpShareInfo)))){
		goto Err;
	}

	pSftpShare->share = strdup(pShare->szName);
	pSftpShare->path = strdup(pShare->szPath);
	pSftpShare->perm.szShareName = pSftpShare->share;
	pSftpShare->blOnlyACL = blOnlyACL;
	MapToSftpPerm(IS_ADMIN(pUser), pShare->fFTPPrivilege, iPriv, &(pSftpShare->perm));

#ifdef MY_ABC_HERE
	if (0 > SYNORecycleStatusGet(pSftpShare->share, &pSftpShare->enableRecycleBin)) {
		SYSLOG(LOG_ERR, "SYNORecycleStatusGet failed! share[%s]", pSftpShare->share);
	}
	if (0 > SYNORecycleAdminOnlyStatusGet(pSftpShare->share, &pSftpShare->blRecycleBinAdminOnly)) {
		SYSLOG(LOG_ERR, "SYNORecycleAdminOnlyStatusGet failed! share[%s]. Disable it. " SLIBERR_FMT, pSftpShare->share, SLIBERR_ARGS);
		pSftpShare->blRecycleBinAdminOnly = FALSE;
	}
#endif /* MY_ABC_HERE */

	//Insert into SFTP Share List
	AppendSftpShare(&(pShares->pShare), pSftpShare);
	
	//Insert into Hash
	pHashShare = (SYNOSftpShareHash *)calloc(1, sizeof(SYNOSftpShareHash));
	StrCP(pHashShare->szShareName, pShare->szName);
	pHashShare->pShare = pSftpShare;
	HASH_ADD_STR(pShares->pHash, szShareName, pHashShare);

	err = 0;
Err:
	if (err) {
		if (pSftpShare) free(pSftpShare);
	}
}

/**
 * Remove '.' and ".." of path 
 * 
 * @param szPath [IN] path may contains '.' or ".."
 * 
 * @return Path without '.' or ".."
 */
char *SYNOSftpPathRemoveDot(const char *szPath)
{
	int err = -1;
	char *szNotDotPath = NULL;
	char *szTokenPath = NULL;
	char *saveptr = NULL;
	char *szToken = NULL;
	char *szEnd = NULL;
	char *szHead = NULL;

	if (!szPath || '\0' == szPath[0]) {
		SYSLOG(LOG_ERR, "Bad parameter");
		return NULL;
	}

	// alloc buffer for: '/' + szPath + '\0'
	if (NULL == (szNotDotPath = xcalloc(1 + strlen(szPath) + 1, sizeof(char))) ||
		NULL == (szTokenPath = xstrdup(szPath))){
		goto Err;
	}

	szNotDotPath[0] = '/';
	szNotDotPath[1] = '\0';
	szHead = szEnd = szNotDotPath;

	if (NULL == (szToken = strtok_r(szTokenPath, "/", &saveptr))) {
		err = 0;
		goto Err;
	}

	do {
		//next token is "." or ".."
		if (!strcmp(szToken, ".")) {
			goto Continue;
		}
		if (!strcmp(szToken, "..")) {
			if (szHead == szEnd) {
				goto Continue;
			}

			// skip last folder name
			szEnd = strrchr(szHead, '/'); 
			if (szHead != szEnd) {
				*szEnd = '\0';
			} else {
				*(szEnd + 1) = '\0';
			}
			goto Continue;
		}

		//next token is normal folder name, append
		*szEnd = '/';
		*(szEnd + 1) = '\0';
		strcat(szEnd, szToken);
		szEnd += (strlen(szToken) + 1); // reach '\0'
Continue:
		szToken = strtok_r(NULL, "/", &saveptr);
	} while (NULL != szToken);

	err = 0;
Err:
	free(szTokenPath);

	if (err) {
		free(szNotDotPath);
		szNotDotPath = NULL;
	}
	return szNotDotPath;
}



static char *GetDupName(const char *szPath)
{
	int maxCounts = 1000;
	int counts = 0;
	char szTmpPath[PATH_MAX];
	char *szNewPath = NULL;
	char *szDupDirPath = NULL;
	char *szDupBasePath = NULL;
	char *szDot = NULL;
	char *szDirName = NULL;
	char *szFileName = NULL;

	if (!szPath) {
		return NULL;
	}

	if ((0 > access(szPath, F_OK)) && (ENOENT == errno)) {
		//file not found, so no need to return duplicated file name
		return NULL;
	}

	if (NULL == (szDupDirPath = xstrdup(szPath)) || 
		NULL == (szDupBasePath = xstrdup(szPath))){
		return NULL;
	}

	//original file exist
	szDirName = dirname(szDupDirPath);
	szFileName = basename(szDupBasePath);	
	if (NULL != (szDot = strrchr(szFileName, '.'))){
		*szDot = '\0';
	}
	for (counts = 1;  maxCounts >= counts;  counts++) {
		if (szDot) {//xxx.xxx
			StrfCP(szTmpPath, "%s/%s (%d).%s", szDirName, szFileName, counts, szDot + 1);
		} else {
			StrfCP(szTmpPath, "%s (%d)", szPath, counts);
		}
		if ((0 > access(szTmpPath, F_OK)) && (ENOENT == errno)) {
			if (NULL == (szNewPath = xstrdup(szTmpPath))){
				SYSLOG(LOG_ERR, "failed to xstrdup(%s) errno:[%m]", szTmpPath);	
			}
			break;
		}
	}

	free(szDupBasePath);
	free(szDupDirPath);

	return szNewPath;
}

static BOOL PermOpenCheck(SYNOSftpPathInfo *pPathInfo, int flags, const char *szOrgName, char ** ppNewName)
{
	if (!pPathInfo->pPerm) {//No Permission
		return FALSE;
	}
	if (IS_ACTION_WRITE(flags)) {
		if (!IS_PERM_WRITE(pPathInfo->pPerm)) {
			return FALSE;
		} else if (!IS_PERM_MODIFY_FILE(pPathInfo->pPerm)) {
			*ppNewName = GetDupName(szOrgName);
		}
	}
	if (IS_ACTION_READ(flags) && !IS_PERM_DOWNLOAD(pPathInfo->pPerm)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL PermRenameCheck(SYNOSftpPerm *pSrcPerm, SYNOSftpPerm *pTrgPerm, const char *szOrgTrgPath, char ** ppNewTrgPath)
{
#ifdef MY_ABC_HERE
	if (pSrcPerm) {//No share, skip checking share permission/
		//Source Check
		if (!IS_PERM_WRITE(pSrcPerm) || !IS_PERM_MODIFY_FILE(pSrcPerm)) {
			return FALSE;
		}
	}

	if (pTrgPerm) {
		//Target Check
		if (!IS_PERM_WRITE(pTrgPerm)) {
			return FALSE;
		} else if (!IS_PERM_MODIFY_FILE(pTrgPerm)) {
			*ppNewTrgPath = GetDupName(szOrgTrgPath);
		}
	}
#endif /* MY_ABC_HERE */

	return TRUE;
}

static int GetUserSharePerm(const SYNOSftpUserInfo *pUser, const PSYNOSHARE pShare, SYNOSftpPerm *pPerm)
{
	int err = -1;
	int iPriv;

	if (!pUser || !pShare || !pPerm) {
		return -1;
	}

	if (0 > GetUserPrivOnShare(pUser, pShare, &iPriv)){
		SYSLOG(LOG_ERR, "failed to get share [%s] privilege for user [%s]. "SLIBERR_FMT, pUser->szName, pShare->szName, SLIBERR_ARGS);
		goto Err;
	}

	MapToSftpPerm(IS_ADMIN(pUser), pShare->fFTPPrivilege, iPriv, pPerm);

	err = 0;
Err:
	return err;
}

static void GetHomePerm(SYNOSftpPerm *pPerm, char *szShareName)
{
	bzero(pPerm, sizeof(*pPerm));
	pPerm->sharePriv = SHARE_RW;
	pPerm->szShareName = szShareName;
}

static int GetChrootInfo(const SYNO_SFTP_CONFIG *pSftpConf, SYNOSftpUserInfo *pUser, const char *szHomeDir, SYNOSftpChrootInfo *pChroot)
{
	int err = -1;
	char szChrootPath[PATH_MAX] = "";
	char szRealPath[PATH_MAX] = "";
	char szSharePath[PATH_MAX] = "";
	char szShareName[SYNO_SHARENAME_UTF8_MAX] = "";
	struct stat stBuf = {0};
	BOOL blChrootIsHomeShare = FALSE;
	BOOL blHomeExist = FALSE;
	PSYNOSHARE pShare = NULL;

	pChroot->blRecycleBin = FALSE;
	pChroot->blRecycleBinAdminOnly = FALSE;

	if (IS_ANONYMOUS(pUser)) {//Anonymous
		if (pSftpConf->isAnonyEnable && pSftpConf->isAnonyChrootEnable) {
			pChroot->isEnable = TRUE;
		}
		if (pSftpConf->szAnonyChrootShareName) {
			if (0 > SYNOShareGet(pSftpConf->szAnonyChrootShareName, &pShare)){
				SYSLOG(LOG_ERR, "failed to get share [%s]. "SLIBERR_FMT, pSftpConf->szAnonyChrootShareName, SLIBERR_ARGS);
				goto Err;
			}
			if (0 > GetUserSharePerm(pUser, pShare, &(pChroot->perm))){
				goto Err;
			}
			pChroot->perm.szShareName = pSftpConf->szAnonyChrootShareName;
			pChroot->szHomePath = xstrdup(pShare->szPath);
			pChroot->szHomeShare = xstrdup(pSftpConf->szAnonyChrootShareName);

			if (0 > SYNORecycleStatusGet(pSftpConf->szAnonyChrootShareName, &pChroot->blRecycleBin)) {
				SYSLOG(LOG_ERR, "SYNORecycleStatusGet failed! share[%s]", pSftpConf->szAnonyChrootShareName);
			}
			if (0 > SYNORecycleAdminOnlyStatusGet(pSftpConf->szAnonyChrootShareName, &pChroot->blRecycleBinAdminOnly)) {
				SYSLOG(LOG_ERR, "SYNORecycleAdminOnlyStatusGet failed! share[%s]", pSftpConf->szAnonyChrootShareName);
			}
		}
		err = 0;
		goto Err;
	}

	//Create Home Directory if not exist
	if (SYNOServiceUserHomeIsEnabled(pUser->authType, NULL)) {
		blHomeExist = TRUE;
		if (0 > SLIBServiceHomePathCreate(pUser->szName)) {
			SYSLOG(LOG_ERR, "Cannot create home directory for '%s', message: %m, "SLIBERR_FMT, pUser->szName, SLIBERR_ARGS);
			blHomeExist = FALSE;
		}
	}

	if (pSftpConf->isChrootEnable && 0 > SYNOFTPChrootPathGet(pUser->szName, szChrootPath, sizeof(szChrootPath), &blChrootIsHomeShare)) {
		if (ERR_NO_SUCH_SHARE != SLIBCErrGet()) {
			SYSLOG(LOG_ERR, "Failed to SYNOFTPChrootPathGet(). [%s]" SLIBERR_FMT, pUser->szName, SLIBERR_ARGS);
		}
		goto Err;
	}

	// early return for non-chroot user
	if (!pSftpConf->isChrootEnable || '\0' == szChrootPath[0]) {
		GetHomePerm(&(pUser->chroot.perm), NULL);
		if (blHomeExist) {
			if (NULL == realpath(szHomeDir, szRealPath)) {
				SYSLOG(LOG_ERR, "Failed to realpath(). [%s]" SLIBERR_FMT, szHomeDir, SLIBERR_ARGS);
				goto Err;
			}
			pChroot->szHomePath = xstrdup(szRealPath);
		} else {
			pChroot->szHomePath = xstrdup(szHomeDir);
		}
		pChroot->isEnable = FALSE;
		err = 0;
		goto Err;
	}

	pChroot->isEnable = TRUE;

	if (!blHomeExist && blChrootIsHomeShare) {
		SYSLOG(LOG_ERR, "Cannot chroot to home share since it does not exist. [%s]", pUser->szName);
		goto Err;
	}

	if (blChrootIsHomeShare) {
		//Give full control.
		GetHomePerm(&(pUser->chroot.perm), NULL);
		if (blHomeExist) {
			if (NULL == realpath(szHomeDir, szRealPath)) {
				SYSLOG(LOG_ERR, "Failed to realpath(). [%s]" SLIBERR_FMT, szHomeDir, SLIBERR_ARGS);
				goto Err;
			}
			pChroot->szHomePath = xstrdup(szRealPath);
		} else {
			pChroot->szHomePath = xstrdup(szChrootPath);
		}
		pChroot->szHomeShare = xstrdup(SZK_RSECTION_HOME);
		pChroot->blRecycleBin = SYNORecycleHomeShareStatusGet();
		if (0 > SYNORecycleAdminOnlyStatusGet(SZK_RSECTION_HOME, &(pChroot->blRecycleBinAdminOnly))) {
			SYSLOG(LOG_ERR, "SYNORecycleAdminOnlyStatusGet home failed. Disable it. " SLIBERR_FMT, SLIBERR_ARGS);
		}
	} else {
		if (0 > stat(szChrootPath, &stBuf)) {
			if (ENOENT != errno) {
				SYSLOG(LOG_ERR, "Failed to stat(). [%s] [%s] [%m]", pUser->szName, szChrootPath);
			} else {
				SYSLOG(LOG_ERR, "The chroot folder [%s] for [%s] does not exist.", szChrootPath, pUser->szName);
			}
			goto Err;
		}
		if (!S_ISDIR(stBuf.st_mode)) {
			SYSLOG(LOG_ERR, "The chroot folder [%s] for [%s] does not exist.", szChrootPath, pUser->szName);
			goto Err;
		}
		if (0 > SYNOShareNamePathGet(szChrootPath, szShareName, sizeof(szShareName), szSharePath, sizeof(szSharePath))) {
			SYSLOG(LOG_ERR, "Failed to SYNOShareNamePathGet().");
			goto Err;
		}
		if (0 > SYNOShareGet(szShareName, &pShare)) {
			SYSLOG(LOG_ERR, "Failed to SYNOShareGet()." SLIBERR_FMT, SLIBERR_ARGS);
			goto Err;
		}
		if (0 > GetUserSharePerm(pUser, pShare, &(pChroot->perm))) {
			SYSLOG(LOG_ERR, "Failed to GetUserSharePerm()." SLIBERR_FMT, SLIBERR_ARGS);
			goto Err;
		}
		if (0 > SYNORecycleStatusGet(pShare->szName, &pChroot->blRecycleBin)) {
			SYSLOG(LOG_ERR, "SYNORecycleStatusGet failed! share[%s]", pShare->szName);
		}
		if (0 > SYNORecycleAdminOnlyStatusGet(pShare->szName, &pChroot->blRecycleBinAdminOnly)) {
			SYSLOG(LOG_ERR, "SYNORecycleAdminOnlyStatusGet failed! share[%s]", pShare->szName);
		}
		pChroot->szHomePath = xstrdup(szChrootPath);
		pChroot->szHomeShare = xstrdup(pShare->szName);
	}

	err = 0;
Err:
	SYNOShareFree(pShare);

	return err;
}

static void FreeUserInfo(SYNOSftpUserInfo *pUser)
{
	if (!pUser) {
		return;
	}

	SLIBCSzListFree(pUser->pGroupList);
	if (pUser->szName) {
		free(pUser->szName);
	}
	if (pUser->chroot.szHomePath) {
		free(pUser->chroot.szHomePath);
	}
	if (pUser->chroot.szHomeShare) {
		free(pUser->chroot.szHomeShare);
	}
	bzero(pUser, sizeof(*pUser));
}

static int GetUserInfo(const struct passwd *pw, const SYNO_SFTP_CONFIG *pSftpConf, SYNOSftpUserInfo *pUser)
{
	int err = -1;

	if (!pw || !pSftpConf || !pUser) {
		return -1;
	}

	//General Information
	pUser->szName = xstrdup(pw->pw_name);
	pUser->uid = pw->pw_uid;
	pUser->gid = pw->pw_gid;
	pUser->authType = SYNOGetAuthType(pw->pw_name);
	if (AUTH_MIN == pUser->authType) {
		SYSLOG(LOG_ERR, "Unknown user type:[%s]", pw->pw_name);
		goto Err;
	}

	//Is Admin
	if (1 == SLIBGroupIsAdminGroupMem(pUser->szName, FALSE)) {
		pUser->userType = SFTP_USER_ADMIN;//Is Admin Group members
	} else if (IS_USERNAME_FTP(pUser->szName) || IS_USERNAME_ANONYMOUS(pUser->szName)) {
		pUser->userType = SFTP_USER_ANONYMOUS;
	} else {
		pUser->userType = SFTP_USER_GENERAL;
	}

	//Groups
	if (NULL == (pUser->pGroupList = SLIBGroupInfoListGet(pw->pw_name, TRUE))) {
		SYSLOG(LOG_ERR,"Failed to get group list of user [%s]."SLIBERR_FMT, pw->pw_name, SLIBERR_ARGS);
		goto Err;
	}

	//Chroot information: load information at the end of function.
	if (0 > GetChrootInfo(pSftpConf, pUser, pw->pw_dir, &pUser->chroot)){
		goto Err;
	}

#ifdef SYNO_SFTP_DEBUG_LOG
	SYSLOG(LOG_ERR, "User: %s, /etc/passwd Home: %s, User Syno Home: %s"
		   , pUser->szName, pw->pw_dir, pUser->chroot.szHomePath);
#endif /* SYNO_SFTP_DEBUG_LOG */
	err = 0;
Err:
	if (err) {
		FreeUserInfo(pUser);
	}
	return err;
}

static void AppendHomeShare(const SYNOSftpUserInfo *pUser, SYNOSftpValidShares *pShares)
{
	int err = -1;
	SYNOSftpShareInfo *pSftpShare = NULL;
	SYNOSftpShareHash *pHashShare = NULL;
	PSYNOSHARE pShare = NULL;
	BOOL blOnlyACL = FALSE;

	if (IS_ANONYMOUS(pUser) || !SYNOServiceUserHomeIsEnabled(pUser->authType, NULL)){
		return;
	}

	//Prepare Share.
	if (NULL == (pSftpShare = (SYNOSftpShareInfo *)calloc(1, sizeof(SYNOSftpShareInfo)))){
		goto Err;
	}

	if (0 > SYNOShareGet(SZK_SECTION_HOMES, &pShare)) {
		SYSLOG(LOG_ERR, "Fail to SYNOShareGet()." SLIBERR_FMT, SLIBERR_ARGS);
		goto Err;
	}
	if (0 > SLIBShareIsOnlyAcl(pShare, &blOnlyACL)) {
		SYSLOG(LOG_ERR, "Fail to SLIBShareIsOnlyAcl()." SLIBERR_FMT, SLIBERR_ARGS);
		goto Err;
	}

	pSftpShare->share = strdup(SZD_SHARE_HOME);
	pSftpShare->path = strdup(pUser->chroot.szHomePath);
	pSftpShare->blOnlyACL = blOnlyACL;
	GetHomePerm(&(pSftpShare->perm), pSftpShare->share);

#ifdef MY_ABC_HERE
	pSftpShare->enableRecycleBin = SYNORecycleHomeShareStatusGet();
	if (0 > SYNORecycleAdminOnlyStatusGet("home", &pSftpShare->blRecycleBinAdminOnly)) {
		SYSLOG(LOG_ERR, "SYNORecycleAdminOnlyStatusGet home failed. Disable it. "SLIBERR_FMT, SLIBERR_ARGS);
		pSftpShare->blRecycleBinAdminOnly = FALSE;
	}
#endif /* MY_ABC_HERE */
	//Insert into SFTP Share List
	AppendSftpShare(&(pShares->pShare), pSftpShare);

	//Insert into Hash
	pHashShare = (SYNOSftpShareHash *)calloc(1, sizeof(SYNOSftpShareHash));
	StrCP(pHashShare->szShareName, pSftpShare->share);
	pHashShare->pShare = pSftpShare;
	HASH_ADD_STR(pShares->pHash, szShareName, pHashShare);

	err = 0;
Err:
	if (pShare) {
		SYNOShareFree(pShare);
	}
	if (err) {
		if (pSftpShare) free(pSftpShare);
	}
}

static int EnumShares(const SYNOSftpUserInfo *pUser, SYNOSftpValidShares *pShares)
{
	int i = 0;
	int err = -1;
	int counts = 0;
	const char *pszShare = NULL;
	PSYNOSHARE pShare = NULL;
	PSLIBSZLIST pShareList = NULL;
	int iPriv;
	BOOL blOnlyACL = FALSE;

	if (NULL == (pShareList = SLIBCSzListAlloc(BUFSIZ))) {
		SYSLOG(LOG_ERR, "Fail to SLIBCSzListAlloc()." SLIBERR_FMT, SLIBERR_ARGS);
		goto Err;
	}

	if (0 > SYNOShareEnum(&pShareList,
			(SYNOSHAREENUM)(SYNO_SHARE_ENUM_ALL |
			                SYNO_SHARE_ENUM_ENCRYPT_DEC |
			                SYNO_SHARE_ENUM_CLUSTER_ENABLE |
			                SYNO_SHARE_ENUM_C2SHARE |
			                SYNO_SHARE_ENUM_COLD_STORAGE_VOL |
			                SYNO_SHARE_ENUM_WORM_SHARE))) {
		SYSLOG(LOG_ERR, "Fail to SYNOShareEnum()." SLIBERR_FMT, SLIBERR_ARGS);
		goto Err;
	}

	//Start to read
	for (i = 0; i < pShareList->nItem; i++) {
		if (NULL == (pszShare = SLIBCSzListGet(pShareList, i))) {
			SYSLOG(LOG_ERR, "Fail to SLIBCSzListGet()." SLIBERR_FMT, SLIBERR_ARGS);
			goto Err;
		}
		if (0 > SYNOShareGet(pszShare, &pShare)) {
			SYSLOG(LOG_ERR, "Fail to SYNOShareGet()." SLIBERR_FMT, SLIBERR_ARGS);
			goto Err;
		}

		if (0 > GetUserPrivOnShare(pUser, pShare, &iPriv)){
			continue;
		}
		if (0 > SLIBShareIsOnlyAcl(pShare, &blOnlyACL)) {
			goto Err;
		}
		if (!blOnlyACL && (SHARE_NA == iPriv || SHARE_IS_DISABLED(pShare))) {
			continue;
		}
		AppendShares(pShares, pUser, pShare, iPriv, blOnlyACL);
		counts++;
	}

	AppendHomeShare(pUser, pShares);

	err = counts;
Err:
	if (pShare) {
		SYNOShareFree(pShare);
	}
	if (pShareList) {
		SLIBCSzListFree(pShareList);
	}

	return err;
}

#ifdef MY_ABC_HERE
#include <synosdk/user.h>
/*
 * Initialize bandwidth control config.
 *
 * return:
 *     0: success,
 *   -1: error,
 */
int SFTPBWControlInit(const char *szUserName, SYNO_BANDWIDTH_CONFIG *pConfig)
{
	int err = -1;
	uid_t uid = UID_ERR;

	if (NULL == szUserName || NULL == pConfig) {
		goto End;
	}

	// obtain uid
	if (0 > SYNOUserGetUGID(szUserName, &uid, NULL)) {
		SYSLOG(LOG_ERR, "SYNOUserGetUGID failed. user:[%s] "SLIBERR_FMT, szUserName, SLIBERR_ARGS);
		goto End;
	}

	// load config
	if (0 > SYNOBandwidthConfigGet(uid, SYNO_BW_PROTOCOL_FTP, pConfig)) {
		SYSLOG(LOG_ERR, "SYNOBandwidthConfigGet failed. uid:[%u] "SLIBERR_FMT, uid, SLIBERR_ARGS);
		goto End;
	}

	err = 0;

End:

	return err;
}
#endif /* MY_ABC_HERE */

static int LoadConfig(struct passwd *user_pw, SYNOSftpSessionConfig *pConf)
{
	int err = -1;
	SYNOSftpUserInfo *pUser = &pConf->user;

	SYNOSFTPConfigFree(&pConf->sftp);
	if (0 > SYNOSFTPConfigGet(SFTP_CONF_GENERAL, &pConf->sftp)){
		SYSLOG(LOG_ERR, "failed to get sftp config for user [%s]. "SLIBERR_FMT, user_pw->pw_name, SLIBERR_ARGS);
		goto Err;
	}

	FreeUserInfo(pUser);
	if (0 > GetUserInfo(user_pw, &pConf->sftp, pUser)){
		SYSLOG(LOG_ERR, "failed to get user info:[%s]", user_pw->pw_name);
		goto Err;
	}

	FreeValidShares(&pConf->shares);
	if (!IS_CHROOT(pUser)) {
		if (0 > EnumShares(pUser, &pConf->shares)){
			goto Err;
		}
	}

	BZERO_STRUCT(pConf->status);

	pConf->blDefaultUnixPermission = SYNOFTPUmaskEnabledGet();
#ifdef MY_ABC_HERE
	SYNOBandwidthConfigFree(&pConf->BWconfig);
	// Get bandwidth control config for user
	if (0 > SFTPBWControlInit(user_pw->pw_name, &pConf->BWconfig)) {
		SYSLOG(LOG_ERR, "SFTP Bandwidth Control config initializes failed!");
	}
#endif /* MY_ABC_HERE */
	err = 0;
Err:
	return err;
}

int gHupSignal = 0;

static void sighupHandler(int sig)
{
	gHupSignal = 1;
}

struct passwd *pwcopy(struct passwd *);
static struct passwd * MapAnonymousToFTP(struct passwd *pw)
{
#ifdef MY_ABC_HERE
	if (IS_USERNAME_ANONYMOUS(pw->pw_name)) {
		struct passwd *pwOut;
	
		if (NULL == (pwOut = getpwnam(SZD_FTP))){
			SYSLOG(LOG_ERR, "failed to getpwnam (%s), errno=%m", SZD_FTP);
		}
	
		return pwcopy(pwOut);
	}
#endif /* MY_ABC_HERE */
	return pw;
}

static BOOL IsUserInGroup(const char *szGroup, const PSLIBSZLIST  pGroupList)
{
	int i = 0;

	if (!pGroupList) {
		return FALSE;
	}

	EACH_LIST_MEMBER(pGroupList, i) {
		if (!strcmp(szGroup, SLIBCSzListGet(pGroupList, i))){
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL IsSystemInternalUser(const SYNOSftpSessionConfig *pConf)
{
	BOOL blIsSysUser = FALSE; 
	FILE *pf;
	char szBuf[BUFSIZ], *p;
	const SYNOSftpUserInfo *pUser = NULL;

	if (!pConf) {
		SYSLOG(LOG_ERR, "conf can NOT be NULL");
		return FALSE;
	}

	pUser = &pConf->user;

	//Check Anonymous
	if (IS_ANONYMOUS(pUser) && !pConf->sftp.isAnonyEnable) {
		return TRUE;
	}

	//Check User forbidden to login.
	pf = fopen(SZF_USER_NO_LOGIN, "r");
	if (pf == NULL) {
		SYSLOG(LOG_ERR, "Failed to open no login list for user (%s). errno:(%m)", pUser->szName);
		goto Err;
	}

	while (fgets(szBuf, sizeof(szBuf), pf)) {
		if (0 >= SLIBCStrTrimSpaceThenUnwrapInplace(szBuf, sizeof(szBuf))){
			SYSLOG(LOG_ERR, "Failed to trim buffer (%s).", szBuf);
			goto Err;
		}
		p = szBuf;

		if ('#' == *p  || 0 == *p) {
			continue;
		}
		if ('@' == *p) {
			// Group
			p++;
			if (IsUserInGroup(p, pUser->pGroupList)) {
				blIsSysUser = TRUE;
				break;
			}
		} else {
			// User
			if (0 == strcmp(p, pUser->szName)) {
				blIsSysUser = TRUE;
				break;
			}
		}
	}

Err:
	if (pf) {
		fclose(pf);
	}

	return blIsSysUser;
}

static BOOL CanUserLogin(const SYNOSftpSessionConfig *pConf, const char *szIP)
{
#ifdef MY_ABC_HERE
	if (IsSystemInternalUser(pConf)) {
		return FALSE;
	}
#endif /* MY_ABC_HERE */

	return TRUE;
}

static int SetEUID(const SYNOSftpUserInfo *pUser)
{
	if (IS_ADMIN(pUser)) {
		return 0; //Is Admin Group members
	}

	//Not admin group
	if (0 > setegid(pUser->gid)) {
		SYSLOG(LOG_ERR, "[euid: %u] failed to setegid for user [%s] group gid: [%d], errno=%m", geteuid(), pUser->szName, pUser->gid);
		return -1;
	}
	if (0 > initgroups(pUser->szName, pUser->gid)){
		SYSLOG(LOG_ERR, "failed to initgroups [%s], gid: [%d], errno=%m", pUser->szName, pUser->gid);
		return -1;
	}
	if (0 > seteuid(pUser->uid)) {
		SYSLOG(LOG_ERR, "failed to seteuid to user [%s], uid: [%d], errno=%m", pUser->szName, pUser->uid);
		return -1;
	}

	return 0;
}

static int EventBeforeSftpStart(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	BOOL isPermDenied = FALSE;
	struct passwd *pw = pIn->pw;
	char *szIP = pIn->clientAddr;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	const SYNOSftpUserInfo *pUser = NULL;

	if (!pw || !szIP || !pConf) {
		SYSLOG(LOG_ERR, "bad parameter");
		return -1;
	}

	signal(SIGHUP, sighupHandler);

	if (NULL == (pw = MapAnonymousToFTP(pw))) {
		goto Err;
	}

	if (0 > LoadConfig(pw, pConf)){
		SYSLOG(LOG_ERR, "failed to load sftp config for user [%s]. "SLIBERR_FMT, pw->pw_name, SLIBERR_ARGS);
		goto Err;
	}

	pUser = &pConf->user;

	if (!CanUserLogin(pConf, szIP)) {
		isPermDenied = TRUE;
		fprintf(stderr, "Permission denied, please try again.\n");
		goto Err;
	}

	pConf->status.isLogin = TRUE;

	// SLIBLogSet needs this env to get the correct username. (used in connection log)
	if (IS_ANONYMOUS(pUser)) {
		setenv("USERNAME", SYNO_ANONYMOUSE_DISPLAYNAME, 1);
	} else {
		setenv("USERNAME", pUser->szName, 1);
	}

#ifdef MY_ABC_HERE
	//Clear unused connection when user login. Execute under root mode
	SYNOCurConnRefresh(SZF_SFTPD_CONNECTION_REC);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (0 > SetEUID(pUser)){
		goto Err;
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	//Execute under user mode
	UpdateCurrConnLog(NULL, pConf, szIP);
#endif /* MY_ABC_HERE */

	if (IS_CHROOT(pUser)) {
		if (0 > chdir(pUser->chroot.szHomePath)){
			SYSLOG(LOG_ERR, "failed to chdir:[%s], errno=%m", pUser->chroot.szHomePath);
			goto Err;
		}
	}

	pOut->pw = pw;

	err = 0;
Err:
#ifdef MY_ABC_HERE
	if (pUser) {
		if (err) {
			if (isPermDenied) {
				LogLogin(LOG_LOGIN_REFUSED, pUser->szName, pUser->uid, szIP);
			} else {
				LogLogin(LOG_LOGIN_FAILED, pUser->szName, pUser->uid, szIP);
			}
		} else {
			LogLogin(LOG_LOGIN_SUCCESS, pUser->szName, pUser->uid, szIP);
		}
#ifdef MY_ABC_HERE
		if (pConf->blXferSysLog) {
			SYNOSftpXferSysLog(szIP, pUser->szName, "user \"%s\" logged in", pUser->szName);
		}
#endif /* MY_ABC_HERE */
	}
#endif /* MY_ABC_HERE */
	return err;
}

static int EventBeforeEachReq(SYNOSftpTriggerInput *pInput, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	struct passwd *pw = pInput->pw;
	SYNOSftpSessionConfig *pConf = pInput->pConf;

	if (!pw || !pConf || NULL != pOut) {
		pOut->err = ERR_BAD_PARAMETERS;
		SYSLOG(LOG_ERR, "bad parameter");
		return -1;
	}

	if (gHupSignal) {
		if (0 > LoadConfig(pw, pConf)){
			SYSLOG(LOG_ERR, "failed to load sftp config for user [%s]. "SLIBERR_FMT, pw->pw_name, SLIBERR_ARGS);
			goto Err;
		}
		gHupSignal = 0;
	}

	err = 0;
Err:
	return err;
}

static int EventAfterOpen(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	int fd = pIn->fd;
	BOOL blFileExist = pIn->isFileExist;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
#ifdef MY_ABC_HERE
	int rwflag = pIn->flag;
	char *szPathName = NULL;
	char *szFileName = NULL;
#endif /* MY_ABC_HERE */

	if (!pConf || 0 > fd || NULL != pOut) {
		SYSLOG(LOG_ERR, "bad parameter");
		return -1;
	}

#ifdef MY_ABC_HERE
	szPathName = strdup(pIn->szPath);
	szFileName = basename(szPathName);
	// Bandwidth Control initialized before transmitting
	if (IS_ACTION_WRITE(rwflag)) {
		if (0 > SYNOBandwidthStatusInit(&pConf->BWconfig, SYNO_BW_TRANSFER_UPLOAD, szFileName, &pConf->BWCurrTime, &pConf->bwStatus)) {
			SYSLOG(LOG_ERR, "SYNOBandwidthStatusInit failed. user:[%s] file:[%s] "SLIBERR_FMT, pConf->user.szName, szFileName, SLIBERR_ARGS);
		}
	} else if (IS_ACTION_READ(rwflag)) {
		if (0 > SYNOBandwidthStatusInit(&pConf->BWconfig, SYNO_BW_TRANSFER_DOWNLOAD, szFileName, &pConf->BWCurrTime, &pConf->bwStatus)) {
			SYSLOG(LOG_ERR, "SYNOBandwidthStatusInit failed. user:[%s] file:[%s] "SLIBERR_FMT, pConf->user.szName, szFileName, SLIBERR_ARGS);
		}
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (!blFileExist && IS_ADMIN((&pConf->user))) {
		if (0 > fchown(fd, pConf->user.uid, pConf->user.gid)) {
			SYSLOG(LOG_ERR, "Failed to chown to admin id [%d,%d](%m/%d)", pConf->user.uid, pConf->user.gid, errno);
			goto Err;
		}
	}
#endif /* MY_ABC_HERE */

	err = 0;
Err:
#ifdef MY_ABC_HERE
	if (NULL != szPathName) {
		free(szPathName);
	}
#endif /* MY_ABC_HERE */
	return err;
}

static BOOL MyStat(const char *szPath, mode_t  *pStMode)
{
	struct stat st;

	BZERO_STRUCT(st);
	if (0 > lstat(szPath, &st)) {
		return FALSE;
	}

	*pStMode = st.st_mode;

	return TRUE;
}

static int EventBeforeOpen(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	int flags = pIn->flag;
	char *szVirtualPath = pIn->szPath;
	char *szRealPath = NULL;
	char *szRealDupPath = NULL;
	mode_t    stMode = 0;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpPathInfo pathInfo;

	if (!pConf || !szVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		return -1;
	}

	BZERO_STRUCT(pathInfo);
	if (NULL == (szRealPath = GetPathInfo(&pConf->shares, &pConf->user, szVirtualPath, &pathInfo))) {
		if (IS_SYSTEM_PATH(pathInfo)) {
			pOut->err = ERR_ACCESS_DENIED;
		} else {
			pOut->err = ERR_PATH_NOT_FOUND;
		}
		goto Err;
	}
#ifdef MY_ABC_HERE
	if (IS_SYSTEM_PATH(pathInfo) || !PermOpenCheck(&pathInfo, flags, szRealPath, &szRealDupPath)){
		pOut->err = ERR_ACCESS_DENIED;
		goto Err;
	}
#endif /* MY_ABC_HERE */

	/* For deciding whether chown after uploading file */
	pOut->isFileExist = MyStat(szRealPath, &stMode);
#ifdef MY_ABC_HERE
	if (pOut->isFileExist && S_ISLNK(stMode)) {
		pOut->err = ERR_ACCESS_DENIED;
		goto Err;
	}
#endif /* MY_ABC_HERE */

	pOut->mode = pIn->mode;
	pOut->szRealPath = szRealDupPath ? szRealDupPath: szRealPath;

	err = 0;
Err:
	if (err) {
		if (szRealPath) free(szRealPath);
		if (szRealDupPath) free(szRealDupPath);
	} else {//success
		if (szRealDupPath) free(szRealPath);
	}
	return err;
}

static int EventBeforeRename(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	char *szOldRealPath = NULL;
	char *szNewRealPath = NULL;
	char *szNewDupPath = NULL;
	SYNOSftpPathInfo oldPathInfo;
	SYNOSftpPathInfo newPathInfo;
	char *szOldVirtualPath = pIn->szPath;
	char *szNewVirtualPath = pIn->szPathNew;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
#ifdef MY_ABC_HERE
	char *szFilename = NULL;
	char szSharePath[PATH_MAX] = "";
	char szShareName[SYNO_SHARENAME_UTF8_MAX] = "";
	char szRecyclePath[PATH_MAX] = "";
	BOOL blEnableRecycleBin = FALSE;
	BOOL blRecycleBinAdminOnly= FALSE;
#endif /* MY_ABC_HERE */

	if (!pConf || !szOldVirtualPath || !szNewVirtualPath) {
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	BZERO_STRUCT(oldPathInfo);
	BZERO_STRUCT(newPathInfo);
	if (NULL == (szOldRealPath = GetPathInfo(&pConf->shares, &pConf->user, szOldVirtualPath, &oldPathInfo)) 
		|| NULL == (szNewRealPath = GetPathInfo(&pConf->shares, &pConf->user, szNewVirtualPath, &newPathInfo))) {
		if (IS_SYSTEM_PATH(oldPathInfo) && IS_SYSTEM_PATH(newPathInfo)) {
			pOut->err = ERR_ACCESS_DENIED;
		} else {
			pOut->err = ERR_PATH_NOT_FOUND;
		}
		goto Err;
	}

	if (IS_SYSTEM_PATH(oldPathInfo) || IS_SYSTEM_PATH(newPathInfo) 
		|| !PermRenameCheck(oldPathInfo.pPerm, newPathInfo.pPerm, szNewRealPath, &szNewDupPath)) {
		pOut->err = ERR_ACCESS_DENIED;
		goto Err;
	}

#ifdef MY_ABC_HERE
	szFilename = basename(szOldRealPath);
	if (0 == strcmp(szFilename, SZ_RECYCLE_FOLDER)) {
		if (0 > SYNOShareNamePathGet(szOldRealPath, szShareName, sizeof(szShareName), szSharePath, sizeof(szSharePath))) {
			SYSLOG(LOG_ERR, "Failed to SYNOShareNamePathGet().");
			pOut->err = ERR_ACCESS_DENIED;
			goto Err;
		}
		if (0 > snprintf(szRecyclePath, sizeof(szRecyclePath), "%s/" SZ_RECYCLE_FOLDER, szSharePath)) {
			pOut->err = ERR_ACCESS_DENIED;
			goto Err;
		}
		if (0 == strcmp(szOldRealPath, szRecyclePath)) {
			if (0 > SYNORecycleStatusGet(szShareName, &blEnableRecycleBin)) {
				SYSLOG(LOG_ERR, "SYNORecycleStatusGet failed! share[%s]", szShareName);
				pOut->err = ERR_ACCESS_DENIED;
				goto Err;
			}
			if (0 > SYNORecycleAdminOnlyStatusGet(szShareName, &blRecycleBinAdminOnly)) {
				SYSLOG(LOG_ERR, "SYNORecycleAdminOnlyStatusGet failed! share[%s]." SLIBERR_FMT, szShareName, SLIBERR_ARGS);
				pOut->err = ERR_ACCESS_DENIED;
				goto Err;
			}
			if (blEnableRecycleBin && blRecycleBinAdminOnly) {
				pOut->err = ERR_ACCESS_DENIED;
				goto Err;
			}
		}
	}
#endif /* MY_ABC_HERE */

	pOut->szRealPath = szOldRealPath;
	pOut->szRealPathNew = szNewRealPath;
	if (szNewDupPath) {
		free(szNewRealPath);
		szNewRealPath = NULL;
		pOut->szRealPathNew = szNewDupPath;
	}
	
	err = 0;
Err:
	if (err) {
		if (szOldRealPath) free(szOldRealPath);
		if (szNewRealPath) free(szNewRealPath);
		if (szNewDupPath) free(szNewDupPath);
	}
	return err;
}

static int EventBeforeSetStat(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	char *szRealPath = NULL;
	char *szVirtualPath = pIn->szPath;
	SYNOSftpPathInfo pathInfo;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpShareHash *pFound = NULL;

	if (!pConf || !szVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		return -1;
	}

	BZERO_STRUCT(pathInfo);
	if (NULL == (szRealPath = GetPathInfo(&pConf->shares, &pConf->user, szVirtualPath, &pathInfo))) {
		pOut->err = ERR_PATH_NOT_FOUND;
		goto Err;
	}

#ifdef MY_ABC_HERE
	if (IS_SYSTEM_PATH(pathInfo)) {
		pOut->err = ERR_ACCESS_DENIED;
		goto Err;
	}
	if (pathInfo.pPerm) {
		if ((!IS_PERM_WRITE(pathInfo.pPerm) || !IS_PERM_MODIFY_FILE(pathInfo.pPerm))) {
			pOut->err = ERR_ACCESS_DENIED;
			goto Err;
		}
	}
#endif /* MY_ABC_HERE */
	HASH_FIND_STR(pConf->shares.pHash, pathInfo.pPerm->szShareName, pFound);
	if (pFound) {
		pOut->pShare = pFound->pShare;  // Don't free it, share name from gConf.shares
	}

	pOut->szRealPath = szRealPath;

	err = 0;
Err:
	if (err) {
		if (szRealPath) free(szRealPath);
	}
	return err;
}

static int EventBeforeOpenDir(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	mode_t    stMode = 0;
	char *szRealPath = NULL;
	char *szVirtualPath = pIn->szPath;
	SYNOSftpPathInfo pathInfo;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpUserInfo *pUser = &pConf->user;

	if (!pConf || !szVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		return -1;
	}

	BZERO_STRUCT(pathInfo);
	szRealPath = GetPathInfo(&pConf->shares, pUser, szVirtualPath, &pathInfo);
	if (!szRealPath){
		pOut->err = ERR_PATH_NOT_FOUND;
		goto Err;
	}

	if (SFTP_PATH_ROOT == pathInfo.pathType) {//root
		free(szRealPath);
		szRealPath = NULL;
	} else {// not root for enuming share
#ifdef MY_ABC_HERE
		if (!IS_PERM_READ(pathInfo.pPerm)){
			pOut->err = ERR_ACCESS_DENIED;
			goto Err;
		}
#endif /* MY_ABC_HERE */
		pOut->isFileExist = MyStat(szRealPath, &stMode);
#ifdef MY_ABC_HERE
		if (pOut->isFileExist && S_ISLNK(stMode)) {
			pOut->err = ERR_ACCESS_DENIED;
			goto Err;
		}
#endif /* MY_ABC_HERE */
	}

	pOut->szRealPath = szRealPath;
	pOut->pPerm = pathInfo.pPerm; // Don't free it, permission is from gConf.shares
	pOut->pathType = pathInfo.pathType;

	err = 0;
Err:
	if (err) {
		if (szRealPath) free(szRealPath);
	}
	return err;	
}

static int EventBeforeRemove(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	char *szRealPath = NULL;
	char *szVirtualPath = pIn->szPath;
	SYNOSftpPathInfo pathInfo;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpShareHash *pFound = NULL;

	if (!pConf || !szVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	BZERO_STRUCT(pathInfo);
	szRealPath = GetPathInfo(&pConf->shares, &pConf->user, szVirtualPath, &pathInfo);
	if (!szRealPath){
		if (IS_SYSTEM_PATH(pathInfo)) {
			pOut->err = ERR_ACCESS_DENIED;
		} else {
			pOut->err = ERR_PATH_NOT_FOUND;
		}	
		goto Err;
	}

#ifdef MY_ABC_HERE
	if (IS_SYSTEM_PATH(pathInfo) || 
		!IS_PERM_WRITE(pathInfo.pPerm) || 
		!IS_PERM_MODIFY_FILE(pathInfo.pPerm)) {
		pOut->err = ERR_ACCESS_DENIED;
		goto Err;
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (pConf->sftp.isXferLogEnable) {
		struct stat st;
	
		if (0 > stat(szRealPath, &st)){
			SYSLOG(LOG_ERR, "Failed to stat [%s], errno=%m", szRealPath);
		} else {
			pOut->size = st.st_size;
		}
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	HASH_FIND_STR(pConf->shares.pHash, pathInfo.pPerm->szShareName, pFound);
	if (pFound) {
		pOut->pShare = pFound->pShare;  // Don't free it, share name from gConf.shares
	}
#endif /* MY_ABC_HERE */

	pOut->szRealPath = szRealPath;
	pOut->pPerm = pathInfo.pPerm; // Don't free it, permission is from gConf.shares

	err = 0;
Err:
	if (err) {
		if (szRealPath) free(szRealPath);
	}
	return err;	
}

static int EventBeforeMkdir(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	char *szRealPath = NULL;
	char *szVirtualPath = pIn->szPath;
	SYNOSftpPathInfo pathInfo;
	SYNOSftpSessionConfig *pConf = pIn->pConf;

	if (!pConf || !szVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	BZERO_STRUCT(pathInfo);
	szRealPath = GetPathInfo(&pConf->shares, &pConf->user, szVirtualPath, &pathInfo);
	if (!szRealPath){
		if (IS_SYSTEM_PATH(pathInfo)) {
			pOut->err = ERR_ACCESS_DENIED;
		} else {
			pOut->err = ERR_PATH_NOT_FOUND;
		}
		goto Err;
	}

#ifdef MY_ABC_HERE
	if (IS_SYSTEM_PATH(pathInfo)) {
		pOut->err = ERR_ACCESS_DENIED;
		goto Err;
	}
	if (pathInfo.pPerm) {
		if (!IS_PERM_WRITE(pathInfo.pPerm)) {
			pOut->err = ERR_ACCESS_DENIED;
			goto Err;
		}
	}
#endif /* MY_ABC_HERE */

	pOut->szRealPath = szRealPath;
	pOut->mode = pIn->mode;

	err = 0;
Err:
	if (err) {
		if (szRealPath) free(szRealPath);
	}
	return err;	
}

static int EventAfterMkdir(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	char *szVirtualPath = pIn->szPath;
	char *szRealPath = pIn->szPathNew;
	char *szIP = pIn->clientAddr;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpUserInfo *pUser = &pConf->user;

	if (!pConf || !szRealPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

#ifdef MY_ABC_HERE
	if (IS_ADMIN(pUser)) {
		if (0 > chown(szRealPath, pUser->uid, pUser->gid)){
			if (EACCES == errno) {
				pOut->err = ERR_ACCESS_DENIED;
			} else {
				pOut->err = ERR_SYS_UNKNOWN;
			}
			SYSLOG(LOG_ERR, "failed to chown dir [%s] to [%s,uid: (%u), gid: (%u)], errno=%m", szRealPath, pUser->szName, pUser->uid, pUser->gid);
		}
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (pConf->sftp.isXferLogEnable) {
		if (0 > SYNOLogFTPXferLogEx(szIP, pConf, "create folder", 0, szVirtualPath, 1)) {
			SYSLOG(LOG_ERR, "Failed to xfer log PUT(%s,%s,%s,%s), "SLIBERR_FMT
				   , szIP, pConf->user.szName, "create folder", szVirtualPath, SLIBERR_ARGS);
		}
	}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (pConf->blXferSysLog) {
		SYNOSftpXferSysLog(szIP, pConf->user.szName, "mkdir \"%s\"", szVirtualPath);
	}
#endif /* MY_ABC_HERE */

	return 0;	
}

static int EventBeforeRmdir(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	char *szRealPath = NULL;
	char *szVirtualPath = pIn->szPath;
	SYNOSftpPathInfo pathInfo;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpUserInfo *pUser = &pConf->user;

	if (!pConf || !szVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	BZERO_STRUCT(pathInfo);
	szRealPath = GetPathInfo(&pConf->shares, pUser, szVirtualPath, &pathInfo);
	if (!szRealPath){
		if (IS_SYSTEM_PATH(pathInfo)) {
			pOut->err = ERR_ACCESS_DENIED;
		} else {
			pOut->err = ERR_PATH_NOT_FOUND;
		}
		goto Err;
	}

#ifdef MY_ABC_HERE
	if (IS_SYSTEM_PATH(pathInfo) ||
		!IS_PERM_WRITE(pathInfo.pPerm)) {
		pOut->err = ERR_ACCESS_DENIED;
		goto Err;
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	BecomeRoot();
	SYNOEARemoveDanglingEADir(szRealPath);
	UnBecomeRoot(pUser);
#endif /* MY_ABC_HERE */

	pOut->szRealPath = szRealPath;

	err = 0;
Err:
	if (err) {
		if (szRealPath) free(szRealPath);
	}
	return err;	
}

static int EventBeforeStat(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	char *szRealPath = NULL;
	char *szVirtualPath = pIn->szPath;
	SYNOSftpPathInfo pathInfo;
	SYNOSftpSessionConfig *pConf = pIn->pConf;

	if (!pConf || !szVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	BZERO_STRUCT(pathInfo);
	szRealPath = GetPathInfo(&pConf->shares, &pConf->user, szVirtualPath, &pathInfo);
	if (!szRealPath){
		pOut->err = ERR_PATH_NOT_FOUND;
		goto Err;
	}

	if (IS_ROOT_PATH(szRealPath)){
		pOut->err = ERR_SUCCESS;
		goto Err;
	}

	pOut->szRealPath = szRealPath;

	err = 0;
Err:
	if (err) {
		if (szRealPath) free(szRealPath);
	}
	return err;	
}

static int EventBeforeSymlink(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	char *szRealPath = NULL;
	char *szVirtualPath = pIn->szPath;
	SYNOSftpPathInfo pathInfo;
	SYNOSftpSessionConfig *pConf = pIn->pConf;

	if (!pConf || !szVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	BZERO_STRUCT(pathInfo);
	szRealPath = GetPathInfo(&pConf->shares, &pConf->user, szVirtualPath, &pathInfo);
	if (!szRealPath){
		if (IS_SYSTEM_PATH(pathInfo)) {
			pOut->err = ERR_ACCESS_DENIED;
		} else {
			pOut->err = ERR_PATH_NOT_FOUND;
		}
		goto Err;
	}

#ifdef MY_ABC_HERE
	if (IS_SYSTEM_PATH(pathInfo) || !IS_PERM_WRITE(pathInfo.pPerm)) {
		pOut->err = ERR_ACCESS_DENIED;
		goto Err;
	}
#endif /* MY_ABC_HERE */

	pOut->szRealPath = szRealPath;

	err = 0;
Err:
	if (err) {
		if (szRealPath) free(szRealPath);
	}
	return err;	
}

static int EventBeforeStatVfs(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	char *szRealPath = NULL;
	char *szVirtualPath = NULL;
	SYNOSftpPathInfo pathInfo;
	SYNOSftpSessionConfig *pConf = NULL;

	if (!pIn || !pOut) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	szVirtualPath = pIn->szPath;
	pConf = pIn->pConf;

	if (!pConf || !szVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	BZERO_STRUCT(pathInfo);
	szRealPath = GetPathInfo(&pConf->shares, &pConf->user, szVirtualPath, &pathInfo);
	if (!szRealPath){
		goto Err;
	}

	pOut->szRealPath = szRealPath;

	err = 0;
Err:
	if (err) {
		if (szRealPath) free(szRealPath);
	}
	return err;
}

static int EventBeforeHardlink(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	char *szOldRealPath = NULL;
	char *szNewRealPath = NULL;
	char *szOldVirtualPath = NULL;
	char *szNewVirtualPath = NULL;
	SYNOSftpPathInfo oldPathInfo;
	SYNOSftpPathInfo newPathInfo;
	SYNOSftpSessionConfig *pConf = NULL;

	if (!pIn || !pOut) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	szOldVirtualPath = pIn->szPath;
	szNewVirtualPath = pIn->szPathNew;
	pConf = pIn->pConf;

	if (!pConf || !szOldVirtualPath || !szNewVirtualPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

	BZERO_STRUCT(oldPathInfo);
	BZERO_STRUCT(newPathInfo);
	if (NULL == (szOldRealPath = GetPathInfo(&pConf->shares, &pConf->user, szOldVirtualPath, &oldPathInfo))
		|| NULL == (szNewRealPath = GetPathInfo(&pConf->shares, &pConf->user, szNewVirtualPath, &newPathInfo))) {
		if (IS_SYSTEM_PATH(oldPathInfo) || IS_SYSTEM_PATH(newPathInfo)) {
			pOut->err = ERR_ACCESS_DENIED;
		} else {
			pOut->err = ERR_PATH_NOT_FOUND;
		}
		goto Err;
	}

#ifdef MY_ABC_HERE
	if (IS_SYSTEM_PATH(newPathInfo) || !IS_PERM_WRITE(newPathInfo.pPerm)) {
		pOut->err = ERR_ACCESS_DENIED;
		goto Err;
	}
#endif /* MY_ABC_HERE */

	pOut->szRealPath = szOldRealPath;
	pOut->szRealPathNew = szNewRealPath;

	err = 0;
Err:
	if (err) {
		if (szOldRealPath) free(szOldRealPath);
		if (szNewRealPath) free(szNewRealPath);
	}
	return err;
}

static int EventAfterClose(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int fd = pIn->fd;
	int flags = 0;
	char *szVirtualPath = pIn->szPath;
	char *szRealPath = pIn->szPathNew;
	char *szIP = pIn->clientAddr;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpFileHandle *pFH = &pIn->fH;
#ifdef MY_ABC_HERE
	int rwflag = pIn->flag;

	// remove bandwidth control status file
	if (IS_ACTION_WRITE(rwflag)) {
		if (0 >SYNOBandwidthStatusRemove(&pConf->BWconfig, SYNO_BW_TRANSFER_UPLOAD)) {
			SYSLOG(LOG_ERR, "SYNOBandwidthStatusRemove failed."SLIBERR_FMT, SLIBERR_ARGS);
		}
	} else if (IS_ACTION_READ(rwflag)) {
		if (0 >SYNOBandwidthStatusRemove(&pConf->BWconfig, SYNO_BW_TRANSFER_DOWNLOAD)) {
			SYSLOG(LOG_ERR, "SYNOBandwidthStatusRemove failed."SLIBERR_FMT, SLIBERR_ARGS);
		}
	}
#endif /* MY_ABC_HERE */

	if (pFH->isFile) {
		if (!pConf || !szVirtualPath || !szRealPath || !szIP) {
			SYSLOG(LOG_ERR, "bad parameter (%s, %s, %s)", szVirtualPath, szRealPath, szIP);
			pOut->err = ERR_BAD_PARAMETERS;
			return -1;
		}

		flags = fcntl(fd, F_GETFL);

#ifdef SYNO_SFTP_DEBUG_LOG
		SYSLOG(LOG_ERR, "flags: %d, read: [%d], write: [%d], sizeof(off_t): [%d], szVirtualPath: [%s], username: %s, is_file: %d, read: [%llu], write: [%llu]"
			   , flags, IS_OPEN_READ(flags), IS_OPEN_WRITE(flags)
			   , sizeof(off_t), szVirtualPath, pConf->user.szName, pFH->isFile, pFH->ullReadBytes, pFH->ullWriteBytes);
#endif /* SYNO_SFTP_DEBUG_LOG */

		if (pFH->ullReadBytes > 0 || IS_OPEN_READ(flags)) {
#ifdef MY_ABC_HERE
			pConf->status.readBytes += pFH->ullReadBytes;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
			if (pConf->sftp.isXferLogEnable) {
				if (0 > SYNOLogFTPXferLogEx(szIP, pConf, "get", pFH->ullReadBytes, szVirtualPath, 0)) {
					SYSLOG(LOG_ERR, "Failed to xfer log GET(%s,%s,%s,%llu,%s)"SLIBERR_FMT
						   , szIP, pConf->user.szName, "get", pFH->ullReadBytes, szVirtualPath, SLIBERR_ARGS);
				}
			}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
			if (pConf->blXferSysLog) {
				SYNOSftpXferSysLog(szIP, pConf->user.szName, "download \"%s\" (size = %llu)", szVirtualPath, pFH->ullReadBytes);
			}
#endif /* MY_ABC_HERE */
		}
		if (pFH->ullWriteBytes > 0 || IS_OPEN_WRITE(flags)){
#ifdef MY_ABC_HERE
			pConf->status.writeBytes += pFH->ullWriteBytes;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
			if (pConf->sftp.isXferLogEnable) {
				if (0 > SYNOLogFTPXferLogEx(szIP, pConf, "put", pFH->ullWriteBytes, szVirtualPath, 0)) {
					SYSLOG(LOG_ERR, "Failed to xfer log PUT(%s,%s,%s,%llu,%s), "SLIBERR_FMT
						   , szIP, pConf->user.szName, "get", pFH->ullReadBytes, szVirtualPath, SLIBERR_ARGS);
				}
			}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
			if (pConf->blXferSysLog) {
				SYNOSftpXferSysLog(szIP, pConf->user.szName, "upload \"%s\" (size = %llu)", szVirtualPath, pFH->ullWriteBytes);
			}
#endif /* MY_ABC_HERE */
		}
	}

	return 0;
}

static int EventAfterRemove(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	off_t size = pIn->size;
	char *szVirtualPath = pIn->szPath;
	char *szRealPath = pIn->szPathNew;
	char *szIP = pIn->clientAddr;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpUserInfo *pUser = &pConf->user;

	if (!pConf || !szRealPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

#ifdef MY_ABC_HERE
	if (0 != SYNOEARemove(szRealPath, -1, NULL)) {
		SYSLOG(LOG_ERR, "Failed to remove EA of directory [%s] (%s,%s,%s), "SLIBERR_FMT
				   , szRealPath, szIP, pUser->szName, szVirtualPath, SLIBERR_ARGS);
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (pConf->sftp.isXferLogEnable) {
		if (0 > SYNOLogFTPXferLogEx(szIP, pConf, "delete", size, szVirtualPath, 0)) {
			SYSLOG(LOG_ERR, "Failed to xfer log (%s,%s,%s,%s, %llu), "SLIBERR_FMT
				   , szIP, pUser->szName, "delete file", szVirtualPath, size, SLIBERR_ARGS);
		}
	}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (pConf->blXferSysLog) {
		SYNOSftpXferSysLog(szIP, pUser->szName, "delete \"%s\" (size = %llu)", szVirtualPath, size);
	}
#endif /* MY_ABC_HERE */

	return 0;	
}

static int EventAfterRmdir(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	char *szVirtualPath = pIn->szPath;
	char *szRealPath = pIn->szPathNew;
	char *szIP = pIn->clientAddr;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpUserInfo *pUser = &pConf->user;

	if (!pConf || !szRealPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

#ifdef MY_ABC_HERE
	if (0 != SYNOEARemove(szRealPath, -1, NULL)) {
		SYSLOG(LOG_ERR, "Failed to remove EA of directory [%s] (%s,%s,%s), "SLIBERR_FMT
				   , szRealPath, szIP, pUser->szName, szVirtualPath, SLIBERR_ARGS);
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (pConf->sftp.isXferLogEnable) {
		if (0 > SYNOLogFTPXferLogEx(szIP, pConf, "delete folder", 0, szVirtualPath, 1)) {
			SYSLOG(LOG_ERR, "Failed to xfer log (%s,%s,%s,%s), "SLIBERR_FMT
				   , szIP, pUser->szName, "delete folder", szVirtualPath, SLIBERR_ARGS);
		}
	}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (pConf->blXferSysLog) {
		SYNOSftpXferSysLog(szIP, pUser->szName, "rmdir \"%s\"", szVirtualPath);
	}
#endif /* MY_ABC_HERE */

	return 0;	
}

static int EventBeforeSftpStop(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	char *szIP = pIn->clientAddr;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNOSftpUserInfo *pUser = &pConf->user;

	if (!pConf || !szIP || NULL != pOut) {
		SYSLOG(LOG_ERR, "bad parameter");
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

#ifdef MY_ABC_HERE
	if (pConf->status.isLogin) {
		LogLogout(pUser->szName, pUser->uid, szIP, pConf->status.writeBytes, pConf->status.readBytes);
	}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (pConf->blXferSysLog) {
		SYNOSftpXferSysLog(szIP, pUser->szName, "user \"%s\" logged out", pUser->szName);
	}
#endif /* MY_ABC_HERE */

	return 0;
}

static int EventAfterOpenDir(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int err = -1;
	SYNOSftpPerm *pPerm = pIn->pPerm;
	SYNOSftpSessionConfig *pConf = pIn->pConf;
	SYNO_PATH_TYPE pathType = pIn->pathType;
	char *szIP = pIn->clientAddr;
	char *szShareName = NULL;

	if (!pConf || !szIP) {
		SYSLOG(LOG_ERR, "bad parameter (%d/%d/%d)", !pConf, !pPerm, !szIP);
		return -1;
	}

#ifdef MY_ABC_HERE
	if (SFTP_PATH_ROOT != pathType) { //ROOT has no permission
		szShareName = pPerm->szShareName;
	}

	if (0 > UpdateCurrConnLog(szShareName, pConf, szIP)){
		goto Err;
	}
#endif /* MY_ABC_HERE */

	err = 0;
Err:
	return err;	
}

static int EventAfterRename(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	char *szOldRealPath = pIn->szPath;
	char *szNewRealPath = pIn->szPathNew;
	SYNOSftpSessionConfig *pConf = pIn->pConf;

	if (!pConf || !szOldRealPath || !szNewRealPath) {
		pOut->err = ERR_BAD_PARAMETERS;
		return -1;
	}

#ifdef MY_ABC_HERE
	if (0 != SYNOEARename(szOldRealPath, szNewRealPath, -1, NULL)) {
		SYSLOG(LOG_ERR, "Failed to rename EA from oldname[%s], newname[%s], errno=%m"
			   , szOldRealPath, szNewRealPath);
	}
#endif /* MY_ABC_HERE */

	return 0;
}

static int EventAfterSetStat(SYNOSftpTriggerInput *pIn, SYNOSftpTriggerOutput *pOut)
{
	int setstRet = pIn->setstRet;
	char *szRealPath = pIn->szPath;
	SYNOSftpSessionConfig *pConf = pIn->pConf;

	if (!pConf || !szRealPath) {
		SYSLOG(LOG_ERR, "bad parameter");
		return -1;
	}

	return 0;
}

struct tag_event_handler
{
	SFTP_OP_EVENT e;
	int (*op)(SYNOSftpTriggerInput *, SYNOSftpTriggerOutput *);
} gEHandler[] = {
	{SFTP_EVENT_BEFORE_REQUEST, &EventBeforeEachReq},
	{SFTP_EVENT_BEFORE_SFTP_START, &EventBeforeSftpStart},
	{SFTP_EVENT_BEFORE_SFTP_STOP, &EventBeforeSftpStop},
	{SFTP_EVENT_BEFORE_OPEN, &EventBeforeOpen},
	{SFTP_EVENT_AFTER_OPEN, &EventAfterOpen},
	{SFTP_EVENT_BEFORE_RENAME, &EventBeforeRename},
	{SFTP_EVENT_AFTER_RENAME, &EventAfterRename},
	{SFTP_EVENT_BEFORE_SETSTAT, &EventBeforeSetStat},
	{SFTP_EVENT_AFTER_SETSTAT, &EventAfterSetStat},
	{SFTP_EVENT_BEFORE_OPENDIR, &EventBeforeOpenDir},
	{SFTP_EVENT_AFTER_OPENDIR, &EventAfterOpenDir},
	{SFTP_EVENT_BEFORE_REMOVE, &EventBeforeRemove},
	{SFTP_EVENT_AFTER_REMOVE, &EventAfterRemove},
	{SFTP_EVENT_BEFORE_MKDIR, &EventBeforeMkdir},
	{SFTP_EVENT_AFTER_MKDIR, &EventAfterMkdir},
	{SFTP_EVENT_BEFORE_RMDIR, &EventBeforeRmdir},
	{SFTP_EVENT_AFTER_RMDIR, &EventAfterRmdir},
	{SFTP_EVENT_BEFORE_STAT, &EventBeforeStat},
	{SFTP_EVENT_BEFORE_SYMLINK, &EventBeforeSymlink},
	{SFTP_EVENT_BEFORE_STATVFS, &EventBeforeStatVfs},
	{SFTP_EVENT_BEFORE_HARDLINK, &EventBeforeHardlink},
	{SFTP_EVENT_AFTER_CLOSE, &EventAfterClose},
	{SFTP_EVENT_NONE, NULL}
};

int SYNOSftpTrigger(SFTP_OP_EVENT e, SYNOSftpTriggerInput *pInput, SYNOSftpTriggerOutput *pOut)
{
	int i = 0;
	int err = -1;
	while(gEHandler[i].op) {
		if (e == gEHandler[i].e) {
			err = (*gEHandler[i].op)(pInput, pOut);
			break;
		}
		i++;
	}

	return err;
}

int SYNOSftpErrGetBy(SYNOERR err)
{
	switch (err) {
	case ERR_PATH_NOT_FOUND:
		return SSH2_FX_NO_SUCH_FILE;
	case ERR_ACCESS_DENIED:
		return SSH2_FX_PERMISSION_DENIED;
	case ERR_SUCCESS:
		return SSH2_FX_OK;
	case ERR_BAD_PARAMETERS:
		return SSH2_FX_FAILURE;
	default:
		SYSLOG(LOG_ERR, "UNKNOWN ERROR (0x%X)", err);
		break;
	}
	return -1;
}

#ifdef	MY_ABC_HERE
BOOL SYNOSftpIsVisiblePath(int isDir, const char *szFileName)
{
	if (!isDir) {
		return TRUE;
	}
	return SYNOEAIsHiddenDir(szFileName)?FALSE:TRUE; 
}
#endif /* MY_ABC_HERE */

#endif /* MY_ABC_HERE */



