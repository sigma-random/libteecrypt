/* 
 * Copyright (C) 2013 - 2014 TrustKernel Team - All Rights Reserved
 *
 * This file is part of T6.
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * A full copy of license could be obtained from 
 *
 * 		http://www.trustkernel.org/license/license.txt
 *
 * Written by Wenhao Li <liwenhaosuper@gmail.com>
 *
 */
#ifndef _STAT_H_
#define _STAT_H_

#define T_DIR  1   // Directory
#define T_FILE 2   // File
#define T_DEV  3   // Device

struct stat {
    short   type;  // Type of file
    int     dev;   // File system's disk device
    uint    ino;   // Inode number
    short   nlink; // Number of links to file
    uint    size;  // Size of file in bytes
};
#endif
