#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _SYNODEF_H
#define _SYNODEF_H

#define MY_ABC_HERE  /* ellie: add "-d" option for client to send password*/
#define MY_ABC_HERE /* ellie: for hack prevetion bug #8969*/
#define MY_ABC_HERE /* jwkuo: Add PAM_SILENT flag in pam_authenticate */
#define MY_ABC_HERE /* Refuse empty password login after authentication, for bug #50128 */

// for sshd reference
#define SZF_SSHD_REFERENCE "/usr/syno/etc/sshd.reference"
#define SZ_SSHD_REFERENCE_RSYNC "rsync"
#define SZ_SSHD_REFERENCE_SFTPD "sftpd"
#define SZ_SSHD_REFERENCE_SHELL "shell"

/* Allow Local/Domain/LDAP user use SSH application, like SFTP/SCP, TimeBkp, Rsync
 * Includes: 
 *  	  - bieichu: [DSM] #24688.
 *  	  - ellie:   [DSM] #4255. privilege root and rsync to login by ssh.
 *  	  - ellie:   [DSM] Local/Domain user can do ssh login for rsync, so that everyone can do rsync SSH backup.
 *  	  - JimLin:  [DSM] SFTP/SCP.
 */

#define MY_ABC_HERE /* Convert to real local/domain/ldap user name */

#define MY_ABC_HERE /* stop userauth when OTP is required but not available */


#ifdef MY_ABC_HERE

//#define SYNO_SFTP_DEBUG_LOG 				/* SFTP: Add more debug log */
#define MY_ABC_HERE  				/* SFTP: Hide special folder */
#define MY_ABC_HERE	  				/* SFTP: User/Anonymous chroot */
#define MY_ABC_HERE 			/* SFTP: Add Share privilege */
#define MY_ABC_HERE 			/* SFTP: Add Application privilege */
#define MY_ABC_HERE 					/* SFTP: Write pid file for sftpd */
#define MY_ABC_HERE						/* SFTP: Extended Attribute */
#define MY_ABC_HERE			/* SFTP: Not allow symbolic link */
#define MY_ABC_HERE				/* SFTP: Use UNIX default umask */

#ifdef MY_ABC_HERE
#define MY_ABC_HERE				/* SFTP: Transfer Log */
#define MY_ABC_HERE					/* SFTP: Connection Log */
#define MY_ABC_HERE			/* SFTP: Current connection Status */
#define MY_ABC_HERE			/* SFTP: Transfer Log (by syslog) */
#endif

#ifdef MY_ABC_HERE
#define MY_ABC_HERE 		/* SFTP: Not allow root/guest to login SFTP */
#define MY_ABC_HERE 		/* SFTP: Allow anonymous login as ftp */
#define MY_ABC_HERE  			/* SFTP: Members in admin-group should be root */
#define MY_ABC_HERE					/* SSH: Write connection log only in shell */
#define MY_ABC_HERE				/* RSYNC: rsync skip auth after sshd auth success */
#define MY_ABC_HERE					/* SSH: Support ACL for key file permission check */
#endif

#endif /* MY_ABC_HERE */

#ifdef SYNO_SOFS_LSYNCD
#define SOFS_DEF_RSYNC_SSHD_PORT 876
#endif /* SYNO_SOFS_LSYNCD */

#endif	/* SYNODEF_H */

