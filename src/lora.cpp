#include <stdio.h>
#include <string.h>

#include "lora.h"
#include "mbedtls/base64.h"				/* mbed TLS for decoding base64 */
#include "mbedtls/aes.h"				/* for decryping the FRMPayload */


/**
 * Decrypt the FRMPayload in the given PhyPayload structure.
 * Decryption is done in place, so the FRMPayLoad field of phy_payload
 * will contain the plaintext payload
 *
 * @param	phy_payload	Pointer to PhyPayload whose FRMPayload needs to be decrypted
 * @param	aesKey		AES key for decryption
 *
 * @return 	Nonzero on success, zero on failure
 */
int decrypt_frmpayload(PhyPayload * phy_payload, const unsigned char * aesKey)
{
	mbedtls_aes_context aes_ctx;
	unsigned char aes_nonce_counter[16];
	unsigned char aes_stream_block[16];
	unsigned char FRMPayload_decrypted[250];
	size_t aes_offset = 0;


	mbedtls_aes_init(&aes_ctx);
	mbedtls_aes_setkey_enc(&aes_ctx, aesKey, 128);
	/* Construct counter for using CTR mode on AES
	 * The format of the counter is specified in the LoraWan specification
	 * WARNING: any of the nonce counter's (multi-byte) subfields are little-endian
	 * */
	memset(aes_stream_block, 0, 16);
	memset(aes_nonce_counter, 0, 16);
	aes_nonce_counter[0] = 0x01;	// hard-coded constant from spec
	// aes_nonce_counter[1-4] == 0 already from memset
	aes_nonce_counter[5] = 0; 		// Uplink frame = 0
	// aes_nonce_counter[6-9] = DevAddr
	memcpy(&aes_nonce_counter[6], phy_payload->MACPayload.FHDR.DevAddr, sizeof(phy_payload->MACPayload.FHDR.DevAddr));
	// FCnt field is zero extended to 32 bits
	aes_nonce_counter[10] = phy_payload->MACPayload.FHDR.FCnt[0];
	aes_nonce_counter[11] = phy_payload->MACPayload.FHDR.FCnt[1];
	aes_nonce_counter[12] = 0x00;
	aes_nonce_counter[13] = 0x00;
	//aes_nonce_counter[14] == 0 already from memset
	// actual "counter" that is incremented in CTR mode for every 16-byte block
	aes_nonce_counter[15] = 1;

	/* Decrypt the FRMPayload using the known AES key */
	if(mbedtls_aes_crypt_ctr(&aes_ctx,
							 phy_payload->MACPayload.FRMPayloadLen,
							 &aes_offset,
							 aes_nonce_counter,
							 aes_stream_block,
							 phy_payload->MACPayload.FRMPayload,
							 phy_payload->MACPayload.FRMPayload) != 0)
	{
		fprintf(stderr, "Error decrypting FRMPayload");
		return 0;
	}

	return 1;
}


int phypayload_parse(PhyPayload * phy_payload, unsigned char * raw_payload, size_t raw_payload_size)
{
	size_t FOptsLen = 0;
	memcpy(&phy_payload->MHDR,
		   raw_payload + offsetof(PhyPayload, MHDR),
		   sizeof(phy_payload->MHDR));
	memcpy(&phy_payload->MACPayload.FHDR.DevAddr,
		   raw_payload + offsetof(PhyPayload, MACPayload.FHDR.DevAddr),
		   sizeof(phy_payload->MACPayload.FHDR.DevAddr));
	memcpy(&phy_payload->MACPayload.FHDR.FCtrl,
		   raw_payload + offsetof(PhyPayload, MACPayload.FHDR.FCtrl),
		   sizeof(phy_payload->MACPayload.FHDR.FCtrl));
	memcpy(&phy_payload->MACPayload.FHDR.FCnt,
		   raw_payload + offsetof(PhyPayload, MACPayload.FHDR.FCnt),
		   sizeof(phy_payload->MACPayload.FHDR.FCnt));

	FOptsLen = (size_t)(phy_payload->MACPayload.FHDR.FCtrl & 0x3);
	memcpy(&phy_payload->MACPayload.FHDR.FOpts,
		   raw_payload + offsetof(PhyPayload, MACPayload.FHDR.FOpts) ,
		   FOptsLen);
	memcpy(&phy_payload->MACPayload.FPort,
		   raw_payload + offsetof(PhyPayload, MACPayload.FHDR.FOpts) + FOptsLen,
		   sizeof(phy_payload->MACPayload.FPort));

	phy_payload->MACPayload.FRMPayloadLen = (size_t) ((raw_payload + raw_payload_size - sizeof(phy_payload->MIC)) 					 /* address of end of frame - MIC */
													   - (raw_payload + offsetof(PhyPayload, MACPayload.FHDR.FOpts) + FOptsLen));                    /* address of beginning of FRMPayLoad */
	memcpy(&phy_payload->MACPayload.FRMPayload, raw_payload+9+FOptsLen, phy_payload->MACPayload.FRMPayloadLen);
	memcpy(&phy_payload->MIC, raw_payload + raw_payload_size - sizeof(phy_payload->MIC), sizeof(phy_payload->MIC));

}
