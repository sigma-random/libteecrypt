#ifndef CRYPT_CTX_H
#define CRYPT_CTX_H

#include <tee_api_types.h>
#include <tee_queue.h>
#include <utee_mem.h>
#include "crypt_state.h"
#include "crypt_engine.h"

//TAILQ_HEAD(tee_crypt_ctx_head, tee_crypt_ctx);
//TAILQ_HEAD(tee_ta_crypt_sess_head, tee_ta_crypt_session);
TAILQ_HEAD(tee_crypt_state_head, tee_crypt_state);
TAILQ_HEAD(tee_obj_head, tee_obj);
//TAILQ_HEAD(tee_storage_enum_head, tee_storage_enum);


/* Context of a  TA Cryption*/
struct tee_crypt_ctx {
	TAILQ_ENTRY(tee_crypt_ctx) link;
	/* list of cryption sessions opened by this TA */
	//struct tee_ta_crypt_session_head open_sessions;
	/* List of cryp states created by this TA */
	struct tee_crypt_state_head cryp_states;
	/* List of storage objects opened by this TA */
	struct tee_obj_head objects;
	/* List of storage enumerators opened by this TA */
	//struct tee_storage_enum_head storage_enums;

	uint32_t context;	/* Context ID of the process */
	uint32_t flags;		/* TA_FLAGS from sub header */
	uint32_t panicked;	/* True if TA has panicked, written from asm */
	uint32_t panic_code;	/* Code supplied for panic */
	uint32_t ref_count;	/* Reference counter for multi session TA */
};

/* Cryption Context Operation Funcs */
TEE_Result tee_init_crypt_ctx();

TEE_Result tee_fini_crypt_ctx();

TEE_Result tee_get_crypt_ctx(struct tee_crypt_ctx **crypt_ctx);

TEE_Result tee_set_crypt_ctx(struct tee_crypt_ctx *crypt_ctx);

#endif