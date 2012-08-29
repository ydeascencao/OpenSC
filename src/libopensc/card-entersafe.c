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

static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;
  
	entersafe_ops = *iso_drv->ops;
	entersafe_ops.match_card = entersafe_match_card;
	entersafe_ops.init   = entersafe_init;

	return &entersafe_drv;
}

struct sc_card_driver * sc_get_entersafe_test_driver(void)
{
	return sc_get_driver();
}
#endif
