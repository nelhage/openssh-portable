#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
// Copyright (c) 2000-2012 Synology Inc. All rights reserved.
#ifndef _SYNOSFTP_LIB_H
#define _SYNOSFTP_LIB_H

#include "synodef.h"

#include <uthash.h>
#include <synosdk/group.h>
#include <synosdk/share.h>
#include <synosdk/user.h>
#include <synocore/list.h>
#include <synoftp.h>
#include <synossh.h>

#ifdef MY_ABC_HERE
#include <synobandwidth/synobandwidth.h>
#endif
#define SZF_ENUM_SHARE_ROOT_PATH "@SHARE"
#define SZF_USER_NO_LOGIN "/etc/ftpusers"
#define SZD_ANONYMOUS "anonymous"
#define	SYNO_ANONYMOUSE_DISPLAYNAME	"Anonymous FTP"
#define SZD_FTP "ftp"
#define SZD_SSHD "sshd"
#define SZD_SFTPD "sftpd"
#define SZD_INTERNAL_SFTP "internal-sftp"
#define SZD_SHARE_HOME "home"

//Connection Log
#define SZF_SYNOLOG_SET "/usr/syno/bin/synologset1"
#define LOG_LOGIN_SUCCESS   0x0001
#define LOG_LOGIN_FAILED    0x0011
#define LOG_LOGIN_REFUSED   0x0013
#define LOG_LOGOUT_SUCCESS  0x0005

#define SZD_LOG_TYPE_WARN   "warn"
#define SZD_LOG_TYPE_INFO   "info"

#define MAX_SHARE_ENUM_ONE_TIME 100
#define IS_ENUM_SHARE_PATH(path) !strcmp(path, SZF_ENUM_SHARE_ROOT_PATH)
#define PERM_IS_DENIED(priv) (0 == priv.all_priv || SHARE_NA == priv.all_priv)
#define SHARE_IS_DISABLED(share) (share->status & SHARE_STATUS_DISABLE)
#define IS_ACTION_WRITE(f) ((f & O_WRONLY) || (f & O_RDWR))
#define IS_ACTION_READ(f) ((O_RDONLY == f) || (f & O_RDWR)) //O_RDONLY is 0
#define IS_PERM_WRITE(p) (SHARE_RW == p->sharePriv)
#define IS_PERM_READ(p) ((SHARE_RO == p->sharePriv) || (SHARE_RW == p->sharePriv))
#define IS_PERM_LISTDIR(p) (!p->disable_ls)
#define IS_PERM_MODIFY_FILE(p) (!p->disable_modifify)
#define IS_PERM_DOWNLOAD(p) (!p->disable_download)
#define USERNAME(c) c->user.szName
#define IS_USERNAME_ANONYMOUS(name) (!strcmp(name, SZD_ANONYMOUS))
#define IS_USERNAME_FTP(name) (!strcmp(name, SZD_FTP))
#define IS_CHROOT(u) ((u)->chroot.isEnable)
#define IS_ADMIN(u) (SFTP_USER_ADMIN == u->userType)
#define IS_ANONYMOUS(u) (SFTP_USER_ANONYMOUS == u->userType)
#define IS_STR_EQUAL(s1, s2) ((s1 && s2 && !strcmp(s1, s2)) || (!s1 && !s2))
#define CWD_SHARE(c) c->status.szShareName
#define SHARE_HASH(conf)  &conf.shares
#define FIRST_SHARE(conf)  conf.shares.pShare
#define EACH_SHARE(s)  for(;s;s=s->next)
#define IS_OPEN_WRITE(f) (f >= 0 && ((f & O_ACCMODE) == O_WRONLY || (f & O_ACCMODE) == O_RDWR))
#define IS_OPEN_READ(f) (f >= 0 && ((f & O_ACCMODE) == O_RDONLY || (f & O_ACCMODE) == O_RDWR))
#define IS_SYSTEM_PATH(p) (SFTP_PATH_SUBFOLDER != p.pathType) //system path can not be modified
#define IS_SHARE_PATH(virtual_path) !strchr(virtual_path + 1, '/')
#define IS_ROOT_PATH(path) !strcmp(path, "/")
#ifdef MY_ABC_HERE
#define CHROOT_HOME_PATH "."
#endif
typedef struct sftpd_permission {
    int sharePriv;
    int disable_download;
    int disable_ls;
    int disable_modifify;
	char * szShareName;
} SYNOSftpPerm;

typedef struct sftpd_chroot_info {
	BOOL isEnable;
	char *szHomePath;
    SYNOSftpPerm perm;
	BOOL blRecycleBin;
	BOOL blRecycleBinAdminOnly;
	char *szHomeShare;
} SYNOSftpChrootInfo;

typedef enum sftpd_user_type {
	SFTP_USER_GENERAL = 0,  //not admin and anonymous
	SFTP_USER_ADMIN,
	SFTP_USER_ANONYMOUS,
}SYNO_USER_TYPE;

typedef enum sftpd_path_type {
	SFTP_PATH_ERR = 0,
	SFTP_PATH_ROOT,
	SFTP_PATH_SHARE,
	SFTP_PATH_SUBFOLDER,
}SYNO_PATH_TYPE;

typedef struct sftpd_path_info {
	SYNOSftpPerm *pPerm;
	SYNO_PATH_TYPE pathType;
} SYNOSftpPathInfo;

typedef struct sftpd_user_info {
	char *szName;
	uid_t uid;
	gid_t gid;
	SYNO_USER_TYPE userType;
	AUTH_TYPE authType;
	PSLIBSZLIST  pGroupList;
	SYNOSftpChrootInfo chroot;
} SYNOSftpUserInfo;

typedef struct sftpd_share_info {
    struct sftpd_share_info *next;
    char *share;
    char *path;
	SYNOSftpPerm perm;
#ifdef MY_ABC_HERE
	BOOL enableRecycleBin;
	BOOL blRecycleBinAdminOnly;
#endif
	BOOL blOnlyACL;
} SYNOSftpShareInfo;

typedef struct sftpd_share_hash_idx {
    char szShareName[SYNO_SHARENAME_UTF8_MAX];
    SYNOSftpShareInfo * pShare;
    UT_hash_handle hh;
} SYNOSftpShareHash;

typedef struct sftpd_valid_share {
    SYNOSftpShareInfo * pShare;
    SYNOSftpShareHash * pHash;
} SYNOSftpValidShares;

typedef struct sftpd_session_status {
	off_t readBytes;
	off_t writeBytes;
	BOOL isLogin;
	char *szShareName; // Now use which share, NULL means chroot into home directory
} SYNOSftpSessionStatus;

typedef struct sftpd_session_config {
    SYNOSftpUserInfo user;
	SYNO_SFTP_CONFIG sftp;
	SYNOSftpValidShares shares;
	SYNOSftpSessionStatus status;
#ifdef MY_ABC_HERE
	SYNO_BANDWIDTH_CONFIG BWconfig;
	SYNO_BANDWIDTH_STATUS bwStatus;
	int64_t BWCurrTime;
#endif
	BOOL blDefaultUnixPermission;
#ifdef MY_ABC_HERE
	BOOL blXferSysLog;
#endif
} SYNOSftpSessionConfig;

typedef struct sftpd_file_handle {
	BOOL isFile;
	unsigned long long ullReadBytes;
	unsigned long long ullWriteBytes;
} SYNOSftpFileHandle;

typedef enum sftpd_setstat_type {
	SFTP_CHMOD = 0x01,
	SFTP_CHOWN = 0x02,
	SFTP_TRUNCATE = 0x04,
	SFTP_MODTIME = 0x08,
}SYNO_SETSTAT_TYPE;

typedef struct sftpd_trigger_input {
	int fd;
	int mode;  			//Linux mode
	int flag;			//flag for open()
	int setstRet;		//SetState result:  bitwise with SYNO_SETSTAT_TYPE
	off_t size;			//file size
	BOOL isFileExist;
	SYNO_PATH_TYPE pathType;  		// for opendir
	char *szShareName;	//Sharename
	char *szPath;		//File Path
	char *szPathNew;	//File Path
	char *clientAddr;	//Remote client address
	struct passwd *pw;
	SYNOSftpFileHandle fH; //Same as struct "Handle" in sftp-server
	SYNOSftpPerm *pPerm;	// user permission on the path.
    SYNOSftpSessionConfig *pConf;
} SYNOSftpTriggerInput;

typedef struct sftpd_trigger_output {
	char *szRealPath;				//Real file path
	char *szRealPathNew;			//New Real file path
	struct passwd *pw;
	int mode;  						//Linux mode
	off_t size;						//file size
	BOOL isFileExist;
	SYNO_PATH_TYPE pathType;  		// for opendir
	SYNOSftpPerm *pPerm;			// user permission on the path.
	SYNOSftpShareInfo *pShare;		// Share Information
	SYNOERR err;
} SYNOSftpTriggerOutput;


typedef enum sftpd_operation_event {
	SFTP_EVENT_NONE = 0, 			//Not really event, only for internal use.
	SFTP_EVENT_BEFORE_SFTP_START,   //SFTP start to execute.
	SFTP_EVENT_BEFORE_SFTP_STOP,    //SFTP exit: maybe logout or connection timeout.
	SFTP_EVENT_BEFORE_REQUEST,    	//Before processing each request.
	SFTP_EVENT_BEFORE_OPEN,    		//Before open().
	SFTP_EVENT_AFTER_OPEN,    		//After open().
	SFTP_EVENT_BEFORE_RENAME,    	//Before rename().
	SFTP_EVENT_AFTER_RENAME,    	//After rename().
	SFTP_EVENT_BEFORE_SETSTAT,    	//Before chown(),truncate(),...
	SFTP_EVENT_AFTER_SETSTAT,    	//After chown(),truncate(),...
	SFTP_EVENT_BEFORE_OPENDIR,    	//Before opendir()
	SFTP_EVENT_AFTER_OPENDIR,    	//After opendir()
	SFTP_EVENT_BEFORE_REMOVE,		//Before unlink()
	SFTP_EVENT_AFTER_REMOVE,		//After unlink()
	SFTP_EVENT_BEFORE_MKDIR,		//Before mkdir()
	SFTP_EVENT_AFTER_MKDIR,			//After mkdir()
	SFTP_EVENT_BEFORE_RMDIR,		//Before rmdir()
	SFTP_EVENT_AFTER_RMDIR,			//After rmdir()
	SFTP_EVENT_BEFORE_STAT,			//Before stat()
	SFTP_EVENT_BEFORE_SYMLINK,    	//Before symlink().
	SFTP_EVENT_BEFORE_STATVFS,	//Before statvfs()
	SFTP_EVENT_BEFORE_HARDLINK,	//Before hardlink()
	SFTP_EVENT_AFTER_CLOSE,    		//After close().
}SFTP_OP_EVENT;

int SYNOSftpTrigger(SFTP_OP_EVENT e, SYNOSftpTriggerInput *pInput, SYNOSftpTriggerOutput *pOut);
int SYNOSftpErrGetBy(SYNOERR err);
char *SYNOSftpPathRemoveDot(const char *szPath);

//Dis-Allow root, guest, ... etc login.
BOOL SYNOSftpIsVisiblePath(int isDir, const char *szFileName);
BOOL SYNOSshCanLogin(BOOL blSFTPCmd, struct passwd * pw);
#ifdef MY_ABC_HERE
int SFTPBWControlInit(const char *szUserName, SYNO_BANDWIDTH_CONFIG *pConfig);
#endif
#ifdef MY_ABC_HERE
void SYNOSftpXferSysLog(const char *szIP, const char *szUser, const char *fmt, ...);
#endif /* MY_ABC_HERE */

#endif /* SYNOSFTP_LIB_H */
