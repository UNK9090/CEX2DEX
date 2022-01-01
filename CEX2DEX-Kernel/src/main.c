/*
 * CEX2DEX Kernel
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/iofilemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/idstorage.h>
#include <taihen.h>
#include <cmep_mgr.h>
#include "../../ef2_types.h"
#include "console_id.h"
#include "idstorage.h"
#include "taihen_macro.h"

#define printf ksceDebugPrintf

// CelesteBlue's Testkit(Fat) cid
const char dex_cid[16] = {
	0x00, 0x00, 0x00, 0x01,
	0x01, 0x02, 0x00, 0x10,
	0x0C, 0x00, 0x07, 0x9F,
	0x10, 0x8D, 0x40, 0x29
};

const char diag_cid[16] = {
	0x00, 0x00, 0x00, 0x01,
	0x01, 0x03, 0x00, 0x10,
	0x90, 0x00, 0x00, 0x10,
	0x00, 0x00, 0x00, 0x00
};

int is_dex;

extern unsigned char __cmep_payload_bin[];
extern unsigned int __cmep_payload_bin_len;

int ef2Hello(void){

	int res;

	Ef2HelloParam hello_param;
	memset(&hello_param, 0, sizeof(hello_param));

	hello_param.auth_word[0] = 0x525BF48D;
	hello_param.auth_word[1] = 0x2D3515DA;
	hello_param.auth_word[2] = 0xD92F11CA;
	hello_param.auth_word[3] = 0x375F730C;

	res = cmepMgrCallFunc(EF2_CMD_HELLO, &hello_param, sizeof(hello_param));
	if(res < 0){
		printf("hello failed\n");
		return res;
	}

	printf("hello success\n");

	return res;
}

int get_hash(const void *src, int len, void *dst){

	int off = 0;

	while(len >= 4){
		*(int *)(dst + (off & 0x1F)) = *(int *)(src + off);
		off += 4;
		len -= 4;
	}

	while(len >= 2){
		*(int *)(dst + (off & 0x1F)) = *(int *)(src + off);
		off += 2;
		len -= 2;
	}

	while(len >= 1){
		*(int *)(dst + (off & 0x1F)) = *(int *)(src + off);
		off += 1;
		len -= 1;
	}

	return 0;
}

int installConsoleId(const void *cid){

	int res;

	res = cmepMgrStart(__cmep_payload_bin, __cmep_payload_bin_len);
	if(res < 0)
		goto end_ef2;

	res = ef2Hello();
	if(res < 0){
		goto end_ef2;
	}

	const char *write_cid = cid;

	if(cid_check(write_cid) < 0){
		res = 0x80FF0000;
		goto end_ef2;
	}

	Ef2IdStorageLeafData param;

	memset(&param, 0, sizeof(param));

	res = ksceIdStorageReadLeaf(0x44, param.data);
	if(res < 0){
		goto end_ef2;
	}

	if(memcmp(&param.data[0xA0], write_cid, 0x10) == 0){
		printf("same cid\n");
		res = 0xFFFFFFFF;
		goto end_ef2;
	}

	memcpy(&param.data[0xA0], write_cid, 0x10);

	res = cmepMgrCallFunc(EF2_CMD_IDSTORAGE_LEAF_RESIGN_68, &param, sizeof(param));
	if(res < 0){
		printf("Resign : 0x%X\n", res);
		goto end_ef2;
	}

	res = cmepMgrCallFunc(EF2_CMD_IDSTORAGE_LEAF_VERIFY_68, &param, sizeof(param));
	if(res < 0){
		printf("Verify : 0x%X\n", res);
		goto end_ef2;
	}

	char hash[0x20];

	get_hash(&param.data[0xA0], 0xE8, hash);

	if(memcmp(hash, param.hash, 0x20) != 0){
		ksceDebugPrintf("%s:Leaf hash not matched\n", __FUNCTION__);
		res = 0x80000000;
		goto end_ef2;
	}

	res = write_idstorage_forced(0x44, param.data);

end_ef2:
	cmepMgrStop();

	return res;
}

int installDexCid(void){
	return installConsoleId(dex_cid);
}

int installOrgCid(void){

	int res;
	char org_cid[0x10], idstorage_buf[0x200];
	SceIoStat stat;
	SceKblParam *kbl_param;

	/*
	 * This check is necessary because uninstalling dex cid from vita with testkit os0 installed will result in bsod brick.
	 */
	res = ksceKernelSearchModuleByName("SceKernelBlueScreenOfDeath");
	if(res >= 0){
		res = ksceIoGetstat("os0:kd/bsod.skprx", &stat);
	}

	if(res >= 0){
		return -1;
	}

	kbl_param = ksceKernelSysrootGetKblParam();
	if(kbl_param == NULL || kbl_param->current_fw_version != 0x3600000){
		return -1;
	}

	res = ksceIdStorageReadLeaf(0x01, idstorage_buf);
	if(res < 0){
		printf("sceIdStorageReadLeaf 01 : 0x%X\n", res);
		return res;
	}

	memcpy(org_cid, &idstorage_buf[0x60], 0x10);

	if(cid_check(org_cid) < 0){
		printf("failed cid check\n");
		return 0x80000000;
	}

	return installConsoleId(org_cid);
}

int _installCustomOpenPsid(const void *open_psid){

	int res;

	res = cmepMgrStart(__cmep_payload_bin, __cmep_payload_bin_len);
	if(res < 0)
		goto end_ef2;

	res = ef2Hello();
	if(res < 0){
		goto end_ef2;
	}

	Ef2IdStorageLeafData2 param;

	memset(&param, 0, sizeof(param));

	res = ksceIdStorageReadLeaf(0x46, param.data);
	if(res < 0){
		printf("sceIdStorageReadLeaf %d : 0x%X\n", 70, res);
		goto end_ef2;
	}

	res = ksceIdStorageReadLeaf(0x47, param.data2);
	if(res < 0){
		printf("sceIdStorageReadLeaf %d : 0x%X\n", 71, res);
		goto end_ef2;
	}

	res = cmepMgrCallFunc(EF2_CMD_IDSTORAGE_LEAF_VERIFY_70, &param, sizeof(param));
	printf("Verify : 0x%X(first)\n", res);

	if(res < 0)
		goto end_ef2;

	memcpy(&param.data[0x128], open_psid, 0x10);

	res = cmepMgrCallFunc(EF2_CMD_IDSTORAGE_LEAF_RESIGN_70, &param, sizeof(param));
	printf("Resign : 0x%X(first)\n", res);

	res = cmepMgrCallFunc(EF2_CMD_IDSTORAGE_LEAF_VERIFY_70, &param, sizeof(param));
	printf("Verify : 0x%X(second)\n", res);

	char hash[0x20];
	char temp[0xE8];

	memcpy(temp, &param.data[0x128], 0xD8);
	memcpy(&temp[0xD8], param.data2, 0x10);

	get_hash(temp, 0xE8, hash);

	if(memcmp(hash, param.hash, 0x20) != 0){
		ksceDebugPrintf("%s:Leaf hash not matched\n", __FUNCTION__);
		res = 0x80000000;
		goto end_ef2;
	}

	res = write_idstorage_forced(0x46, param.data);
	if(res >= 0)
		res = write_idstorage_forced(0x47, param.data2);

end_ef2:
	cmepMgrStop();

	return res;
}

const char DEX_OpenPsid[] = {
	/*
 	 * This openPsid is not DEX openpsid xD
	 */
	/*
	 * This is Princess Vita OpenPSID
	 */
	0xF5, 0x5A, 0xA9, 0x18,
	0xF2, 0x52, 0x16, 0x61,
	0x16, 0x10, 0x50, 0x98,
	0xC0, 0x6D, 0x01, 0xCB
};

int installCustomOpenPsid(void){

	char open_psid[0x10];

	SceUID fd = ksceIoOpen("sd0:new_psid.bin", SCE_O_RDONLY, 0);
	if(fd < 0)
		fd = ksceIoOpen("ux0:new_psid.bin", SCE_O_RDONLY, 0);

	if(fd >= 0){

		SceIoStat stat;
		memset(&stat, 0, sizeof(stat));

		ksceIoGetstatByFd(fd, &stat);

		if(stat.st_size != 0x10LL){
			ksceIoClose(fd);
			goto install_pre_psid;
		}

		ksceIoLseek(fd, 0LL, SCE_SEEK_SET);
		ksceIoRead(fd, open_psid, 0x10);
		ksceIoClose(fd);
	}else{
install_pre_psid:
		memcpy(open_psid, DEX_OpenPsid, 0x10);
	}

	return _installCustomOpenPsid(open_psid);
}

static tai_hook_ref_t ksceSblAIMgrIsDEX_ref;
int ksceSblAIMgrIsDEX_patched(void){

	TAI_CONTINUE(int, ksceSblAIMgrIsDEX_ref);

	return 0;
}

static tai_hook_ref_t ksceSblAIMgrIsCEX_ref;
int ksceSblAIMgrIsCEX_patched(void){

	TAI_CONTINUE(int, ksceSblAIMgrIsCEX_ref);

	return 1;
}

int is_temp_spoofed = 0;

int tempCexSpoof(void){

	int res;

	if(is_temp_spoofed != 0)
		return -1;

	res = cmepMgrStart(__cmep_payload_bin, __cmep_payload_bin_len);
	if(res < 0)
		goto end_ef2;

	res = ef2Hello();
	if(res < 0){
		goto end_ef2;
	}

	int fake_arg[4];

	res = cmepMgrCallFunc(EF2_CMD_F00D_TEMP_CEX_SPOOF, fake_arg, sizeof(fake_arg));
	if(res >= 0){
		HookExport("SceSysmem", 0xFD00C69A, 0xF4B98F66, ksceSblAIMgrIsDEX);
		HookExport("SceSysmem", 0xFD00C69A, 0xD78B04A2, ksceSblAIMgrIsCEX);

		is_temp_spoofed = 1;
	}

end_ef2:
	cmepMgrStop();

	return res;
}

int install_testkit_cid(void){

	int res = -1, state;

	ENTER_SYSCALL(state);

	SceKblParam *kbl_param = ksceKernelSysrootGetKblParam();
	if(is_dex == 0 && kbl_param->current_fw_version == 0x3600000){
		res = installDexCid();
	}else{
		res = -1;
	}

	EXIT_SYSCALL(state);

	return res;
}

int install_org_cid(void){

	int res = -1, state;

	ENTER_SYSCALL(state);

	SceKblParam *kbl_param = ksceKernelSysrootGetKblParam();
	if(kbl_param != NULL && kbl_param->current_fw_version == 0x3600000){
		res = installOrgCid();
	}else{
		res = -1;
	}

	EXIT_SYSCALL(state);

	return res;
}

int verify_open_psid(void){

	int res = -1, state;

	ENTER_SYSCALL(state);
	EXIT_SYSCALL(state);

	return res;
}

int install_open_psid(void){

	int res = -1, state;

	ENTER_SYSCALL(state);

	SceKblParam *kbl_param = ksceKernelSysrootGetKblParam();
	if(kbl_param != NULL && kbl_param->current_fw_version == 0x3600000){
		res = installCustomOpenPsid();
	}else{
		res = -1;
	}

	EXIT_SYSCALL(state);

	return res;
}

int temp_cex_spoof(void){

	int res = -1, state;

	ENTER_SYSCALL(state);

	SceKblParam *kbl_param = ksceKernelSysrootGetKblParam();
	if(kbl_param != NULL && kbl_param->current_fw_version == 0x3600000){
		res = tempCexSpoof();
	}else{
		res = -1;
	}

	EXIT_SYSCALL(state);

	return res;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	SceIoStat stat;

	is_dex = (ksceKernelSearchModuleByName("SceKernelBlueScreenOfDeath") >= 0) ? 1 : 0;
	if(is_dex != 0 && ksceIoGetstat("os0:kd/bsod.skprx", &stat) != 0)
		is_dex = 0;

	ksceDebugPrintf("is_dex : 0x%X\n", is_dex);

	return SCE_KERNEL_START_SUCCESS;
}
