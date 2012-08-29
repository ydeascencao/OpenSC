/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* Initially written by Weitao Sun (weitao@ftsafe.com) 2008 
 * 
 * Sample base driver implementation by Alejandro Diaz (adiaz@emergya.com) 2012
 */

#include "config.h"
#ifdef ENABLE_OPENSSL	/* empty file without openssl */

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

static struct sc_atr_table entersafe_atrs[] = {
	{ 
		 "3b:9f:95:81:31:fe:9f:00:65:46:53:05:30:06:71:df:00:00:00:80:6a:82:5e",
		 "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:00:FF:FF:FF:FF:FF:FF:00:00:00:00",
		 "FTCOS/PK-01C", SC_CARD_TYPE_ENTERSAFE_FTCOS, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations entersafe_ops;
static struct sc_card_operations *iso_ops = NULL;

static struct sc_card_driver entersafe_drv = {
	"entersafe_test",
	"entersafe_test",
	&entersafe_ops,
	NULL, 0, NULL
};

static u8 trans_code_3k[] =
{
	 0x01,0x02,0x03,0x04,
	 0x05,0x06,0x07,0x08,
};

static u8 trans_code_ftcos_pk_01c[] =
{
	 0x92,0x34,0x2E,0xEF,
	 0x23,0x40,0x4F,0xD1,
};

static u8 init_key[] =
{
	 1,  2,  3,  4, 
	 5,  6,  7,  8, 
	 9,  10, 11, 12, 
	 13, 14, 15, 16,
};

static u8 key_maintain[] =
{
	 0x12, 0x34, 0x56, 0x78, 
	 0x21, 0x43, 0x65, 0x87, 
	 0x11, 0x22, 0xaa, 0xbb,
	 0x33, 0x44, 0xcd, 0xef
};

/* the entersafe part */
static int entersafe_match_card(sc_card_t *card)
{
	int i;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	i = _sc_match_atr(card, entersafe_atrs, &card->type);
	if (i < 0)
		return 0;		

	return 1;
}

static int entersafe_init(sc_card_t *card)
{
	unsigned int flags;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	card->name = "entersafe_test";
	card->cla  = 0x00;
	card->drv_data = NULL;

	flags =SC_ALGORITHM_ONBOARD_KEY_GEN
		 | SC_ALGORITHM_RSA_RAW
		 | SC_ALGORITHM_RSA_HASH_NONE;

	_sc_card_add_rsa_alg(card, 512, flags, 0);
	_sc_card_add_rsa_alg(card, 768, flags, 0);
	_sc_card_add_rsa_alg(card,1024, flags, 0);
	_sc_card_add_rsa_alg(card,2048, flags, 0);

	card->caps = SC_CARD_CAP_RNG; 

	/* we need read_binary&friends with max 224 bytes per read */
	card->max_send_size = 224;
	card->max_recv_size = 224;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

/*static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;
  
	entersafe_ops = *iso_drv->ops;
	entersafe_ops.match_card = entersafe_match_card;
	entersafe_ops.init   = entersafe_init;

	return &entersafe_drv;
}*/

/************* FUNCIONES NUEVAS QUE IMPLEMENTAN LA ISO  ***************/

static int entersafe_cipher_apdu(sc_card_t *card, sc_apdu_t *apdu,
								 u8 *key, size_t keylen,
								 u8 *buff, size_t buffsize)
{
	 EVP_CIPHER_CTX ctx;
	 u8 iv[8]={0};
	 int len;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	 assert(card);
	 assert(apdu);
	 assert(key);
	 assert(buff);

	 /* padding as 0x80 0x00 0x00...... */
	 memset(buff,0,buffsize);
	 buff[0]=apdu->lc;
	 memcpy(buff+1,apdu->data,apdu->lc);
	 buff[apdu->lc+1]=0x80;

	 EVP_CIPHER_CTX_init(&ctx);
	 EVP_CIPHER_CTX_set_padding(&ctx,0);

	 if(keylen == 8)
		  EVP_EncryptInit_ex(&ctx, EVP_des_ecb(), NULL, key, iv);
	 else if (keylen == 16) 
		  EVP_EncryptInit_ex(&ctx, EVP_des_ede(), NULL, key, iv);
	 else
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);

	 len = apdu->lc;
	 if(!EVP_EncryptUpdate(&ctx, buff, &len, buff, buffsize)){
		  sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "entersafe encryption error.");
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	 }
	 apdu->lc = len;

	 if (!EVP_CIPHER_CTX_cleanup(&ctx)){
		  sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "entersafe encryption error.");
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	 }

	 if(apdu->lc!=buffsize)
	 {
		  sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "entersafe build cipher apdu failed.");
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INTERNAL);
	 }

	 apdu->data=buff;
	 apdu->datalen=apdu->lc;

	 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int entersafe_gen_random(sc_card_t *card,u8 *buff,size_t size)
{
	 int r=SC_SUCCESS;
	 u8 rbuf[SC_MAX_APDU_BUFFER_SIZE]={0};
	 sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
   
	 sc_format_apdu(card,&apdu,SC_APDU_CASE_2_SHORT,0x84,0x00,0x00);
	 apdu.resp=rbuf;
	 apdu.le=size;
	 apdu.resplen=sizeof(rbuf);

	 r=sc_transmit_apdu(card,&apdu);
	 SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "entersafe gen random failed");

	 if(apdu.resplen!=size)
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,SC_ERROR_INTERNAL);
	 memcpy(buff,rbuf,size);

	 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,r);
}


static int entersafe_mac_apdu(sc_card_t *card, sc_apdu_t *apdu,
							  u8 * key,size_t keylen,
							  u8 * buff,size_t buffsize)
{
	 int r;
	 u8 iv[8];
	 u8 *tmp=0,*tmp_rounded=NULL;
	 size_t tmpsize=0,tmpsize_rounded=0;
	 int outl=0;
	 EVP_CIPHER_CTX ctx;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	 assert(card);
	 assert(apdu);
	 assert(key);
	 assert(buff);

	 if(apdu->cse != SC_APDU_CASE_3_SHORT)
		  return SC_ERROR_INTERNAL;
	 if(keylen!=8 && keylen!=16)
		  return SC_ERROR_INTERNAL;

	 r=entersafe_gen_random(card,iv,sizeof(iv));
	 SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL,r,"entersafe gen random failed");

	 /* encode the APDU in the buffer */
	 if ((r=sc_apdu_get_octets(card->ctx, apdu, &tmp, &tmpsize,SC_PROTO_RAW)) != SC_SUCCESS)
		  goto out;

	 /* round to 8 */
	 tmpsize_rounded=(tmpsize/8+1)*8;

	 tmp_rounded = malloc(tmpsize_rounded);
	 if (tmp_rounded == NULL)
	 {
		  r =  SC_ERROR_OUT_OF_MEMORY;
		  goto out;
	 }

	 /*build content and padded buffer by 0x80 0x00 0x00..... */
	 memset(tmp_rounded,0,tmpsize_rounded);
	 memcpy(tmp_rounded,tmp,tmpsize);
	 tmp_rounded[4]+=4;
	 tmp_rounded[tmpsize]=0x80;

	 /* block_size-1 blocks*/
	 EVP_CIPHER_CTX_init(&ctx);
	 EVP_CIPHER_CTX_set_padding(&ctx,0);
	 EVP_EncryptInit_ex(&ctx, EVP_des_cbc(), NULL, key, iv);

	 if(tmpsize_rounded>8){
		  if(!EVP_EncryptUpdate(&ctx,tmp_rounded,&outl,tmp_rounded,tmpsize_rounded-8)){
			   r = SC_ERROR_INTERNAL;
			   goto out;			   
		  }
	 }
	 /* last block */
	 if(keylen==8)
	 {
		  if(!EVP_EncryptUpdate(&ctx,tmp_rounded+outl,&outl,tmp_rounded+outl,8)){
			   r = SC_ERROR_INTERNAL;
			   goto out;			   
		  }
	 }
	 else
	 {
		  EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, key,tmp_rounded+outl-8);
		  if(!EVP_EncryptUpdate(&ctx,tmp_rounded+outl,&outl,tmp_rounded+outl,8)){
			   r = SC_ERROR_INTERNAL;
			   goto out;			   
		  }
	 }

	 if (!EVP_CIPHER_CTX_cleanup(&ctx)){
		  r = SC_ERROR_INTERNAL;
		  goto out;			   
	 }

	 memcpy(buff,apdu->data,apdu->lc);
	 /* use first 4 bytes of last block as mac value*/
	 memcpy(buff+apdu->lc,tmp_rounded+tmpsize_rounded-8,4);
	 apdu->data=buff;
	 apdu->lc+=4;
	 apdu->datalen=apdu->lc;

out:
	 if(tmp)
		  free(tmp);
	 if(tmp_rounded)
		  free(tmp_rounded);

	 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int entersafe_transmit_apdu(sc_card_t *card, sc_apdu_t *apdu,
								   u8 * key, size_t keylen,
								   int cipher,int mac)
{
	 u8 *cipher_data=0,*mac_data=0;
	 size_t cipher_data_size,mac_data_size;
	 int blocks;
	 int r=SC_SUCCESS;
	u8 *sbuf=NULL;
	size_t ssize=0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	 assert(card);
	 assert(apdu);

	 if((cipher||mac) && (!key||(keylen!=8 && keylen!=16)))
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	r = sc_apdu_get_octets(card->ctx, apdu, &sbuf, &ssize, SC_PROTO_RAW);
	if (r == SC_SUCCESS)
		sc_apdu_log(card->ctx, SC_LOG_DEBUG_VERBOSE, sbuf, ssize, 1);
	free(sbuf);

	 if(cipher)
	 {
		  blocks=(apdu->lc+2)/8+1;
		  cipher_data_size=blocks*8;
		  cipher_data=malloc(cipher_data_size);
		  if(!cipher)
		  {
			   r = SC_ERROR_OUT_OF_MEMORY;
			   goto out;
		  }

		  if((r = entersafe_cipher_apdu(card,apdu,key,keylen,cipher_data,cipher_data_size))<0)
			   goto out;
	 }
	 if(mac)
	 {	 
		  mac_data_size=apdu->lc+4;
		  mac_data=malloc(mac_data_size);
		  r = entersafe_mac_apdu(card,apdu,key,keylen,mac_data,mac_data_size);
		  if(r<0)
			   goto out;
	 }

	 r = sc_transmit_apdu(card,apdu);

out:
	 if(cipher_data)
		  free(cipher_data);
	 if(mac_data)
		  free(mac_data);

	 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int entersafe_read_binary(sc_card_t *card,
								 unsigned int idx, u8 *buf, size_t count,
								 unsigned long flags)
{
	sc_apdu_t apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	assert(count <= card->max_recv_size);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0,
		       (idx >> 8) & 0xFF, idx & 0xFF);

	apdu.cla=idx > 0x7fff ? 0x80:0x00;
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	r = entersafe_transmit_apdu(card, &apdu,0,0,0,0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, apdu.resplen);
}

static int entersafe_update_binary(sc_card_t *card,
								   unsigned int idx, const u8 *buf,
								   size_t count, unsigned long flags)
{
	sc_apdu_t apdu;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	assert(count <= card->max_send_size);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD6,
		       (idx >> 8) & 0xFF, idx & 0xFF);
	apdu.cla=idx > 0x7fff ? 0x80:0x00;
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	r = entersafe_transmit_apdu(card, &apdu,0,0,0,0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, sc_check_sw(card, apdu.sw1, apdu.sw2),
		    "Card returned error");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, count);
}


static int entersafe_restore_security_env(sc_card_t *card, int se_num)
{
	 SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	 return SC_SUCCESS;
}

static int entersafe_internal_set_security_env(sc_card_t *card,
											   const sc_security_env_t *env,
											   u8 ** data,size_t* size)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p=sbuf;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	assert(card != NULL && env != NULL);

	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
	case SC_SEC_OPERATION_SIGN:
		 sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
		 apdu.p1 = 0x41;
		 apdu.p2 = 0xB8;
		 *p++ = 0x80;
		 *p++ = 0x01;
		 *p++ = 0x80;
		 *p++ = 0x83;
		 *p++ = 0x02;
		 *p++ = env->key_ref[0];
		 *p++ = 0x22;
		 if(*size>1024/8)
		 {
			  if(*size == 2048/8)
			  {
				   *p++ = 0x89;
				   *p++ = 0x40;
				   memcpy(p,*data,0x40);
				   p+=0x40;
				   *data+=0x40;
				   *size-=0x40;
			  }
			  else
			  {
				   SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
			  }
		 }
		 break;
	default:
		 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	}

	apdu.le = 0;
	apdu.lc = apdu.datalen = p - sbuf;
	apdu.data = sbuf;
	apdu.resplen = 0;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int entersafe_set_security_env(sc_card_t *card,
									  const sc_security_env_t *env,
									  int se_num)
{
	 assert(card);
	 assert(env);

	 SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	 if(card->drv_data){
		  free(card->drv_data);
		  card->drv_data=0;
	 }

	 card->drv_data = calloc(1,sizeof(*env));
	 if(!card->drv_data)
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_OUT_OF_MEMORY);

	 memcpy(card->drv_data,env,sizeof(*env));
	 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}


static int entersafe_compute_with_prkey(sc_card_t *card,
										const u8 * data, size_t datalen,
										u8 * out, size_t outlen)
{
	int r;
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8* p=sbuf;
	size_t size = datalen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if(!data)
		 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_ARGUMENTS);

	memcpy(p,data,size);

	if(!card->drv_data)
		 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_INTERNAL);

	r = entersafe_internal_set_security_env(card,card->drv_data,&p,&size);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "internal set security env failed");
   
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x86,0x80);
	apdu.data=p;
	apdu.lc = size;
	apdu.datalen = size;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;

	r = entersafe_transmit_apdu(card, &apdu,0,0,0,0);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;
		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int entersafe_decipher(sc_card_t *card,
							  const u8 * crgram, size_t crgram_len,
							  u8 * out, size_t outlen)
{
	 SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	 return entersafe_compute_with_prkey(card,crgram,crgram_len,out,outlen);
}

static int entersafe_compute_signature(sc_card_t *card,
									   const u8 * data, size_t datalen,
									   u8 * out, size_t outlen)
{
	 SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	 return entersafe_compute_with_prkey(card,data,datalen,out,outlen);
}

static void entersafe_init_pin_info(struct sc_pin_cmd_pin *pin, unsigned int num)
{
	pin->encoding   = SC_PIN_ENCODING_ASCII;
	pin->min_length = 4;
	pin->max_length = 16;
	pin->pad_length = 16;
	pin->offset     = 5 + num * 16;
	pin->pad_char   = 0x00;
}

static int entersafe_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
			   int *tries_left)
{
	 int r;
	 SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	 entersafe_init_pin_info(&data->pin1,0);
	 entersafe_init_pin_info(&data->pin2,1);
	 data->flags |= SC_PIN_CMD_NEED_PADDING;

	 if(data->cmd!=SC_PIN_CMD_UNBLOCK)
	 {
		  r = iso_ops->pin_cmd(card,data,tries_left);
		  sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Verify rv:%i", r);
	 }
	 else
	 {
		  {/*verify*/
			   sc_apdu_t apdu;
			   u8 sbuf[0x10]={0};

			   memcpy(sbuf,data->pin1.data,data->pin1.len);
			   sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,0x20,0x00,data->pin_reference+1);
			   apdu.lc = apdu.datalen = sizeof(sbuf);
			   apdu.data = sbuf;

			   r = entersafe_transmit_apdu(card, &apdu,0,0,0,0);
			   SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
		  }

		  {/*change*/
			   sc_apdu_t apdu;
			   u8 sbuf[0x12]={0};

			   sbuf[0] = 0x33;
			   sbuf[1] = 0x00;
			   memcpy(sbuf+2,data->pin2.data,data->pin2.len);
			   sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,0xF4,0x0B,data->pin_reference);
			   apdu.cla = 0x84;
			   apdu.lc = apdu.datalen = sizeof(sbuf);
			   apdu.data = sbuf;

			   r = entersafe_transmit_apdu(card, &apdu,key_maintain,sizeof(key_maintain),1,1);
			   SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
		  }
	 }
	 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}
/*static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;
  
	entersafe_ops = *iso_drv->ops;
	entersafe_ops.match_card = entersafe_match_card;
	entersafe_ops.init   = entersafe_init;

	/* iso7816-4 functions */
	//entersafe_ops.read_binary	= entersafe_read_binary;
	//entersafe_ops.write_binary	= NULL;
	//entersafe_ops.update_binary	= entersafe_update_binary;

	/* iso7816-8 functions */
	//entersafe_ops.restore_security_env = entersafe_restore_security_env;
	//entersafe_ops.set_security_env  = entersafe_set_security_env;
	//entersafe_ops.decipher = entersafe_decipher;
	//entersafe_ops.compute_signature = entersafe_compute_signature;

	/* iso7816-9 functions */
	/*entersafe_ops.pin_cmd = entersafe_pin_cmd;

	return &entersafe_drv;
}*/

static int entersafe_process_fci(struct sc_card *card, struct sc_file *file,
						  const u8 *buf, size_t buflen)
{
	 int r;

	 assert(file);
	 SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	 r = iso_ops->process_fci(card,file,buf,buflen);
	 SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Process fci failed");

	 if(file->namelen)
	 {
		  file->type = SC_FILE_TYPE_DF;
		  file->ef_structure = SC_FILE_EF_UNKNOWN;
	 }
	 else
	 {
		  file->type = SC_FILE_TYPE_WORKING_EF;
		  file->ef_structure = SC_FILE_EF_TRANSPARENT;
	 }

	 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int entersafe_select_file(sc_card_t *card,
								 const sc_path_t *in_path,
								 sc_file_t **file_out);

static int entersafe_select_fid(sc_card_t *card,
								unsigned int id_hi, unsigned int id_lo,
								sc_file_t **file_out)
{
	int r;
	sc_file_t *file=0;
	sc_path_t path;

	memset(&path, 0, sizeof(sc_path_t));

	path.type=SC_PATH_TYPE_FILE_ID;
	path.value[0]=id_hi;
	path.value[1]=id_lo;
	path.len=2;

	r = iso_ops->select_file(card,&path,&file);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	/* update cache */
	if (file->type == SC_FILE_TYPE_DF) {
		 card->cache.current_path.type = SC_PATH_TYPE_PATH;
		 card->cache.current_path.value[0] = 0x3f;
		 card->cache.current_path.value[1] = 0x00;
		 if (id_hi == 0x3f && id_lo == 0x00){
			  card->cache.current_path.len = 2;
		 }else{
			  card->cache.current_path.len = 4;
			  card->cache.current_path.value[2] = id_hi;
			  card->cache.current_path.value[3] = id_lo;
		 }
	}
	
	if (file_out)
		 *file_out = file;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int entersafe_select_aid(sc_card_t *card,
								const sc_path_t *in_path,
								sc_file_t **file_out)
{
	int r = 0;

	if (card->cache.valid 
		&& card->cache.current_path.type == SC_PATH_TYPE_DF_NAME
		&& card->cache.current_path.len == in_path->len
		&& memcmp(card->cache.current_path.value, in_path->value, in_path->len)==0 )
	{
		 if(file_out)
		 {
			  *file_out = sc_file_new();
			  if(!file_out)
				   SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
		 }
	}
	else
	{
		 r = iso_ops->select_file(card,in_path,file_out);
		 SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

		 /* update cache */
		 card->cache.current_path.type = SC_PATH_TYPE_DF_NAME;
		 card->cache.current_path.len = in_path->len;
		 memcpy(card->cache.current_path.value,in_path->value,in_path->len);
	}
	if (file_out) {
		 sc_file_t *file = *file_out;
		 assert(file);

		 file->type = SC_FILE_TYPE_DF;
		 file->ef_structure = SC_FILE_EF_UNKNOWN;
		 file->path.len = 0;
		 file->size = 0;
		 /* AID */
		 memcpy(file->name,in_path->value,in_path->len);
		 file->namelen = in_path->len;
		 file->id = 0x0000;
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int entersafe_select_path(sc_card_t *card,
								const u8 pathbuf[16], const size_t len,
								sc_file_t **file_out)
{
	 u8 n_pathbuf[SC_MAX_PATH_SIZE];
	 const u8 *path=pathbuf;
	 size_t pathlen=len;
	 int bMatch = -1;
	 unsigned int i;
	 int r;

	 if (pathlen%2 != 0 || pathlen > 6 || pathlen <= 0)
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	 /* if pathlen == 6 then the first FID must be MF (== 3F00) */
	 if (pathlen == 6 && ( path[0] != 0x3f || path[1] != 0x00 ))
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);

	 /* unify path (the first FID should be MF) */
	 if (path[0] != 0x3f || path[1] != 0x00)
	 {
		  n_pathbuf[0] = 0x3f;
		  n_pathbuf[1] = 0x00;
		  for (i=0; i< pathlen; i++)
			   n_pathbuf[i+2] = pathbuf[i];
		  path = n_pathbuf;
		  pathlen += 2; 
	 }
	
	 /* check current working directory */
	 if (card->cache.valid 
		 && card->cache.current_path.type == SC_PATH_TYPE_PATH
		 && card->cache.current_path.len >= 2
		 && card->cache.current_path.len <= pathlen )
	 {
		  bMatch = 0;
		  for (i=0; i < card->cache.current_path.len; i+=2)
			   if (card->cache.current_path.value[i] == path[i] 
				   && card->cache.current_path.value[i+1] == path[i+1] )
					bMatch += 2;
	 }

	 if ( card->cache.valid && bMatch > 2 )
	 {
		  if ( pathlen - bMatch == 2 )
		  {
			   /* we are in the rigth directory */
			   return entersafe_select_fid(card, path[bMatch], path[bMatch+1], file_out);
		  }
		  else if ( pathlen - bMatch > 2 )
		  {
			   /* two more steps to go */
			   sc_path_t new_path;
	
			   /* first step: change directory */
			   r = entersafe_select_fid(card, path[bMatch], path[bMatch+1], NULL);
			   SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "SELECT FILE (DF-ID) failed");
	
		   	   memset(&new_path, 0, sizeof(sc_path_t));

			   new_path.type = SC_PATH_TYPE_PATH;
			   new_path.len  = pathlen - bMatch-2;
			   memcpy(new_path.value, &(path[bMatch+2]), new_path.len);
			   /* final step: select file */
			   return entersafe_select_file(card, &new_path, file_out);
		  }
		  else /* if (bMatch - pathlen == 0) */
		  {
			   /* done: we are already in the
				* requested directory */
			   sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				"cache hit\n");
			   /* copy file info (if necessary) */
			   if (file_out) {
					sc_file_t *file = sc_file_new();
					if (!file)
						 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
					file->id = (path[pathlen-2] << 8) +
						 path[pathlen-1];
					file->path = card->cache.current_path;
					file->type = SC_FILE_TYPE_DF;
					file->ef_structure = SC_FILE_EF_UNKNOWN;
					file->size = 0;
					file->namelen = 0;
					file->magic = SC_FILE_MAGIC;
					*file_out = file;
			   }
			   /* nothing left to do */
			   return SC_SUCCESS;
		  }
	 }
	 else
	 {
		  /* no usable cache */
		  for ( i=0; i<pathlen-2; i+=2 )
		  {
			   r = entersafe_select_fid(card, path[i], path[i+1], NULL);
			   SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "SELECT FILE (DF-ID) failed");
		  }
		  return entersafe_select_fid(card, path[pathlen-2], path[pathlen-1], file_out);
	 }
}

static int entersafe_select_file(sc_card_t *card,
								 const sc_path_t *in_path,
								 sc_file_t **file_out)
{
	 int r;
	 char pbuf[SC_MAX_PATH_STRING_SIZE];
	 assert(card);
	 assert(in_path);
	 SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);


	  r = sc_path_print(pbuf, sizeof(pbuf), &card->cache.current_path);
	  if (r != SC_SUCCESS)
		 pbuf[0] = '\0';
		
	  sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		"current path (%s, %s): %s (len: %u)\n",
		   (card->cache.current_path.type==SC_PATH_TYPE_DF_NAME?"aid":"path"),
		   (card->cache.valid?"valid":"invalid"), pbuf,
		   card->cache.current_path.len);
	 
	 switch(in_path->type)
	 {
	 case SC_PATH_TYPE_FILE_ID:
		  if (in_path->len != 2)
			   SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_ARGUMENTS);
		  return entersafe_select_fid(card,in_path->value[0],in_path->value[1], file_out);
	 case SC_PATH_TYPE_DF_NAME:
		  return entersafe_select_aid(card,in_path,file_out);
	 case SC_PATH_TYPE_PATH:
		  return entersafe_select_path(card,in_path->value,in_path->len,file_out);
	 default:
		  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	 }
}

static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;
  
	entersafe_ops = *iso_drv->ops;
	entersafe_ops.match_card = entersafe_match_card;
	entersafe_ops.init   = entersafe_init;

	/* iso7816-4 functions */
	entersafe_ops.read_binary = entersafe_read_binary;
	entersafe_ops.write_binary = NULL;
	entersafe_ops.update_binary = entersafe_update_binary;
	entersafe_ops.select_file = entersafe_select_file;

	/* iso7816-8 functions */
	entersafe_ops.restore_security_env = entersafe_restore_security_env;
	entersafe_ops.set_security_env  = entersafe_set_security_env;
	entersafe_ops.decipher = entersafe_decipher;
	entersafe_ops.compute_signature = entersafe_compute_signature;

	/* iso7816-9 functions */
	entersafe_ops.pin_cmd = entersafe_pin_cmd;
	entersafe_ops.process_fci = entersafe_process_fci;

	return &entersafe_drv;
}

/**********************************************************************/


struct sc_card_driver * sc_get_entersafe_test_driver(void)
{
	return sc_get_driver();
}
#endif
