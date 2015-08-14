/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */ 


#include <tee_api.h>
#include <utee_api.h>
#include <utee_defines.h>
#include <utee_mem.h>
 
#include "teecrypt_api.h"


#define TEE_USAGE_DEFAULT   0xffffffff

#define TEE_ATTR_BIT_VALUE                  (1 << 29)
#define TEE_ATTR_BIT_PROTECTED              (1 << 28)


/* Data and Key Storage API  - Generic Object Functions */
void TEE_GetObjectInfo(TEE_ObjectHandle object, TEE_ObjectInfo *objectInfo)
{
	TEE_Result res;

	res = utee_crypt_obj_get_info((uint32_t)object, objectInfo);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}

}

void TEE_RestrictObjectUsage(TEE_ObjectHandle object, uint32_t objectUsage)
{
	TEE_Result res;

}

TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
					uint32_t attributeID, void *buffer,
					size_t *size)
{
	TEE_Result res;


	return res;
}

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object,
				       uint32_t attributeID, uint32_t *a,
				       uint32_t *b)
{
	TEE_Result res;


	return res;
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
	TEE_Result res;

	if (object == TEE_HANDLE_NULL)
		return;

	res = utee_crypt_obj_close((uint32_t)object);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}

}

/* Data and Key Storage API  - Transient Object Functions */

TEE_Result TEE_AllocateTransientObject(TEE_ObjectType objectType,
				       uint32_t maxObjectSize,
				       TEE_ObjectHandle *object)
{
	TEE_Result res;
	uint32_t obj = 0;
	res = utee_crypt_obj_alloc(objectType, maxObjectSize, &obj);
	if (res == TEE_SUCCESS)
		*object = (TEE_ObjectHandle) obj;
	return res;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	TEE_Result res;
	TEE_ObjectInfo info;

	if (object == TEE_HANDLE_NULL)
		return;

	res = utee_crypt_obj_get_info((uint32_t)object, &info);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}

	if ((info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	res = utee_crypt_obj_close((uint32_t)object);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}

}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
	TEE_Result res;
	TEE_ObjectInfo info;

	if (object == TEE_HANDLE_NULL) {
		return;
	}

	res = utee_crypt_obj_get_info((uint32_t)object, &info);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}

	if ((info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	res = utee_crypt_obj_reset((uint32_t)object);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
				       TEE_Attribute *attrs,
				       uint32_t attrCount)
{
	TEE_Result res;
	TEE_ObjectInfo info;

	res = utee_crypt_obj_get_info((uint32_t)object, &info);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}
	/* Must be a transient object */
	if ((info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Must not be initialized already */
	if ((info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	res = utee_crypt_obj_populate((uint32_t)object, attrs, attrCount);
	if (res != TEE_SUCCESS && res != TEE_ERROR_BAD_PARAMETERS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}

	return res;
}

void TEE_InitRefAttribute(TEE_Attribute *attr, uint32_t attributeID,
			  void *buffer, size_t length)
{
	if (attr == NULL) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	if ((attributeID & TEE_ATTR_BIT_VALUE) != 0) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	attr->attributeID = attributeID;
	attr->content.ref.buffer = buffer;
	attr->content.ref.length = length;
}

void TEE_InitValueAttribute(TEE_Attribute *attr, uint32_t attributeID,
			    uint32_t a, uint32_t b)
{
	if (attr == NULL) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	if ((attributeID & TEE_ATTR_BIT_VALUE) == 0) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	attr->attributeID = attributeID;
	attr->content.value.a = a;
	attr->content.value.b = b;
}

void TEE_CopyObjectAttributes(TEE_ObjectHandle destObject,
			      TEE_ObjectHandle srcObject)
{
	TEE_Result res;
	TEE_ObjectInfo dst_info;
	TEE_ObjectInfo src_info;

	res = utee_crypt_obj_get_info((uint32_t)destObject, &dst_info);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}
	res = utee_crypt_obj_get_info((uint32_t)srcObject, &src_info);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}
	if ((src_info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	if ((dst_info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	if ((dst_info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	res = utee_crypt_obj_copy((uint32_t)destObject, (uint32_t)srcObject);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}

}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize,
			   TEE_Attribute *params, uint32_t paramCount)
{
	TEE_Result res;

	res = tee_crypt_obj_generate_key((uint32_t)object, keySize,
					 params, paramCount);

	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}

	return res;
}

