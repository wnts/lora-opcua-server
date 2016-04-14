/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
	Network sink, receives UDP packets and sends an acknowledge

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Sylvain Miermont
 */


/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

/* fix an issue between POSIX and C99 */
#if __STDC_VERSION__ >= 199901L
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 500
#endif

#include <forward_list>
#include <memory>

#include <stdint.h>		/* C99 types */
#include <stdio.h>		/* printf, fprintf, sprintf, fopen, fputs */
#include <unistd.h>		/* usleep */
#include <stddef.h>		/* offsetof */

#include <string.h>		/* memset */
#include <time.h>		/* time, clock_gettime, strftime, gmtime, clock_nanosleep*/
#include <stdlib.h>		/* atoi, exit */
#include <errno.h>		/* error messages */

#include <sys/socket.h> /* socket specific definitions */
#include <netinet/in.h> /* INET constants and stuff */
#include <arpa/inet.h>  /* IP address conversion stuff */
#include <netdb.h>		/* gai_strerror */

#include "parson.h"		/* JSON parsing */
#include <mbedtls/base64.h>		/* mbed TLS for decoding base64 */
#include <mbedtls/aes.h>		/* for decryping the FRMPayload */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))
#define STRINGIFY(x)	#x
#define STR(x)			STRINGIFY(x)
#define MSG(args...)	fprintf(stderr, args) /* message that is destined to the user */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS ---------------------------------------------------- */

#define	PROTOCOL_VERSION	1

#define PKT_PUSH_DATA	0
#define PKT_PUSH_ACK	1
#define PKT_PULL_DATA	2
#define PKT_PULL_RESP	3
#define PKT_PULL_ACK	4

#define PHYPAYLOAD_BUFSIZE 512

static const unsigned char default_AppSKey[] = {
		0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
		0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

typedef struct {
	unsigned char DevAddr[4];
	unsigned char FCtrl;
	unsigned char FCnt[2];
	unsigned char FOpts[15];
} Fhdr;

typedef struct {
	Fhdr FHDR;
	unsigned char FPort;
	unsigned char FRMPayload[250]; /* Maximum allowed for Datarate 7 */
	unsigned char FRMPayloadLen;
} MacPayload;

/**
 * C Struct representation of a PHYPayload package as
 * specified in the LoraWan specification.
 *
 */
typedef struct {
	unsigned char MHDR;
	MacPayload MACPayload;
	unsigned char MIC[4];
} PhyPayload;

typedef struct {
	struct tm time;
	uint32_t tmst;
	float freq;
	unsigned int chan;
	unsigned int rfch;
	char stat;
	char modu[5] = "";
	unsigned int datr;
	// todo how long should this be?
	char codr[10] = "";
	int rssi;
	float lsnr;
	size_t size;
	// todo how long should this be?
	char base64data[400] = "";
} RxpkObject;

using namespace std;

void print_simple_payload(char * payload)
{
	JSON_Array * values;
	JSON_Value * root_value;
	char * serialized_string = NULL;

	root_value = json_parse_string(payload);
	serialized_string = json_serialize_to_string_pretty(root_value);
	printf(" PAYLOAD :");
	puts(serialized_string);
	json_free_serialized_string(serialized_string);
	json_value_free(root_value);
}
/**
 * Parse the payload of the simple protocol defined by the Packet Forwarder.
 *
 * @param payload	Pointer to buffer containing the root JSON object. This object is
 * 					found in the UDP datagrams sent by the packet forwarder
 * @return	On success a pointer to a list of RxpkObjects.
 * 			On failure, returns a null pointer.
 */
shared_ptr<forward_list<RxpkObject>> parse_simple_payload(const char *payload)
{
	//TODO: there can be a mix of stat/rxpk in one payload
	//TODO: there can be several rxpk objects in one payload
	JSON_Value *payload_root_value;
	JSON_Value *payload_identifier_value;
	JSON_Object *payload_identifier_object;
	JSON_Array *payload_content_array;
	JSON_Object *payload_content_object;
	size_t i;
	const char *time_string;
	const char *data_string;
	shared_ptr<forward_list<RxpkObject>> pRetList = make_shared<forward_list<RxpkObject>>();

	/* parsing json and validating output */
	payload_root_value = json_parse_string(payload);
	if (json_value_get_type(payload_root_value) != JSONObject) {
		MSG("Error: payload root value is not a JSONObject\n");
		goto cleanup;
	}

	payload_identifier_object = json_value_get_object(payload_root_value);
	if (json_object_get_count(payload_identifier_object) != 1) {
		MSG("Error: payload identifier cannot be determined");
		goto cleanup;
	}
	/* Ignore status payloads */
	if (strcmp(json_object_get_name(payload_identifier_object, 0), "stat") == 0) {
		goto cleanup;
	}
	if (strcmp(json_object_get_name(payload_identifier_object, 0), "rxpk") != 0) {
		MSG("Error: payload identifier unkown");
		goto cleanup;
	}

	payload_identifier_value = json_object_get_value(
							   payload_identifier_object,
							   json_object_get_name(payload_identifier_object, 0));
	if (json_value_get_type(payload_identifier_value) != JSONArray) {
		MSG("Error: payload identifier value is not a JSONArray\n");
		goto cleanup;
	}
	pRetList = make_shared<forward_list<RxpkObject>>();
	payload_content_array = json_value_get_array(payload_identifier_value);
	for (i = 0; i < json_array_get_count(payload_content_array); i++) {
		RxpkObject obj;
		const char * stringValue = NULL;
		double numberValue;

		payload_content_object = json_array_get_object(payload_content_array, i);

		/* time */
		stringValue = json_object_get_string(payload_content_object, "time");
		if(stringValue != NULL)
			strptime(stringValue, "%FT%T%z", &obj.time);

		/** tmst, freq, rfch and stat */
		obj.tmst = json_object_get_number(payload_content_object, "tmst");
		obj.freq = json_object_get_number(payload_content_object, "chan");
		obj.rfch = json_object_get_number(payload_content_object, "rfch");
		obj.stat = json_object_get_number(payload_content_object, "stat");
		/* modu */
		stringValue = NULL;
		stringValue = json_object_get_string(payload_content_object, "modu");
		if(stringValue != NULL)
			strncpy(obj.modu, stringValue, sizeof(obj.modu));

		/* datr */
		// todo: check if datr is string datarate identifier and convert to numeric
		obj.datr = json_object_get_number(payload_content_object, "datr");

		/* codr */
		stringValue = NULL;
		stringValue = json_object_get_string(payload_content_object, "codr");
		if(stringValue != NULL)
			strncpy(obj.codr, stringValue, sizeof(obj.codr));

		/* rssi, lsnr and size */
		obj.rssi = json_object_get_number(payload_content_object, "rssi");
		obj.lsnr = json_object_get_number(payload_content_object, "lsnr");
		obj.size = json_object_get_number(payload_content_object, "size");

		/* base64data */
		stringValue = NULL;
		stringValue = json_object_get_string(payload_content_object, "data");
		if(stringValue != NULL)
			strncpy(obj.base64data, stringValue, sizeof(obj.base64data));

		pRetList->push_front(obj);

	}
	/* cleanup code */
cleanup:
	json_value_free(payload_root_value);
	return pRetList;
}

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
	mbedtls_aes_setkey_enc(&aes_ctx, default_AppSKey, 128);
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
		MSG("Error decrypting FRMPayload");
		return 0;
	}


}

/*
 * Map the raw binary representation of the PHY payload onto a C structure
 *
 * @param phy_payload 		Pointer to caller allocated structure
 * @param raw_payload 		Pointer to buffer containing raw_payload
 * @param raw_payload_size	Size of the raw_payload buffer in bytes
 */
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
													   - (raw_payload + offsetof(PhyPayload, MACPayload.FHDR.FOpts) + FOptsLen));    /* address of beginning of FRMPayLoad */
	memcpy(&phy_payload->MACPayload.FRMPayload, raw_payload+9+FOptsLen, phy_payload->MACPayload.FRMPayloadLen);
	memcpy(&phy_payload->MIC, raw_payload + raw_payload_size - sizeof(phy_payload->MIC), sizeof(phy_payload->MIC));

}


/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main(int argc, char **argv)
{
	int i; /* loop variable and temporary variable for return value */

	/* server socket creation */
	int sock; /* socket file descriptor */
	struct addrinfo hints;
	struct addrinfo *result; /* store result of getaddrinfo */
	struct addrinfo *q; /* pointer to move into *result data */
	char host_name[64];
	char port_name[64];

	/* variables for receiving and sending packets */
	struct sockaddr_storage dist_addr;
	socklen_t addr_len = sizeof dist_addr;
	char databuf[4096];
	int byte_nb;

	/* variables for protocol management */
	uint32_t raw_mac_h; /* Most Significant Nibble, network order */
	uint32_t raw_mac_l; /* Least Significant Nibble, network order */
	uint64_t gw_mac; /* MAC address of the client (gateway) */
	uint8_t ack_command;

	PhyPayload phy_payload;
	size_t FOptsLen;
	size_t FRMPayloadLen;




	int rc;

	/* check if port number was passed as parameter */
	if (argc != 2) {
		MSG("Usage: util_ack <port number>\n");
		exit(EXIT_FAILURE);
	}

	/* prepare AES */


	/* prepare hints to open network sockets */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; /* should handle IP v4 or v6 automatically */
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; /* will assign local IP automatically */

	/* look for address */
	i = getaddrinfo(NULL, argv[1], &hints, &result);
	if (i != 0) {
		MSG("ERROR: getaddrinfo returned %s\n", gai_strerror(i));
		exit(EXIT_FAILURE);
	}

	/* try to open socket and bind it */
	for (q=result; q!=NULL; q=q->ai_next) {
		sock = socket(q->ai_family, q->ai_socktype,q->ai_protocol);
		if (sock == -1) {
			continue; /* socket failed, try next field */
		} else {
			i = bind(sock, q->ai_addr, q->ai_addrlen);
			if (i == -1) {
				shutdown(sock, SHUT_RDWR);
				continue; /* bind failed, try next field */
			} else {
				break; /* success, get out of loop */
			}
		}
	}
	if (q == NULL) {
		MSG("ERROR: failed to open socket or to bind to it\n");
		i = 1;
		for (q=result; q!=NULL; q=q->ai_next) {
			getnameinfo(q->ai_addr, q->ai_addrlen, host_name, sizeof host_name, port_name, sizeof port_name, NI_NUMERICHOST);
			MSG("INFO: result %i host:%s service:%s\n", i, host_name, port_name);
			++i;
		}
		exit(EXIT_FAILURE);
	}
	MSG("INFO: util_ack listening on port %s\n", argv[1]);
	freeaddrinfo(result);

	while (1) {
		/* wait to receive a packet */
		byte_nb = recvfrom(sock, databuf, sizeof databuf, 0, (struct sockaddr *)&dist_addr, &addr_len);
		if (byte_nb == -1) {
			MSG("ERROR: recvfrom returned %s \n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* display info about the sender */
		i = getnameinfo((struct sockaddr *)&dist_addr, addr_len, host_name, sizeof host_name, port_name, sizeof port_name, NI_NUMERICHOST);
		if (i == -1) {
			MSG("ERROR: getnameinfo returned %s \n", gai_strerror(i));
			exit(EXIT_FAILURE);
		}
		printf(" -> pkt in , host %s (port %s), %i bytes", host_name, port_name, byte_nb);

		/* check and parse the payload */
		if (byte_nb < 12) { /* not enough bytes for packet from gateway */
			printf(" (too short for GW <-> MAC protocol)\n");
			continue;
		}
		/* don't touch the token in position 1-2, it will be sent back "as is" for acknowledgement */
		if (databuf[0] != PROTOCOL_VERSION) { /* check protocol version number */
			printf(", invalid version %u\n", databuf[0]);
			continue;
		}
		raw_mac_h = *((uint32_t *)(databuf+4));
		raw_mac_l = *((uint32_t *)(databuf+8));
		gw_mac = ((uint64_t)ntohl(raw_mac_h) << 32) + (uint64_t)ntohl(raw_mac_l);

		/* interpret gateway command */
		switch (databuf[3]) {
		case PKT_PUSH_DATA:
			printf(", PUSH_DATA from gateway 0x%08X%08X\n", (uint32_t)(gw_mac >> 32), (uint32_t)(gw_mac & 0xFFFFFFFF));
			ack_command = PKT_PUSH_ACK;
			printf("<-  pkt out, PUSH_ACK for host %s (port %s)", host_name, port_name);
			break;
		case PKT_PULL_DATA:
			printf(", PULL_DATA from gateway 0x%08X%08X\n", (uint32_t)(gw_mac >> 32), (uint32_t)(gw_mac & 0xFFFFFFFF));
			ack_command = PKT_PULL_ACK;
			printf("<-  pkt out, PULL_ACK for host %s (port %s)", host_name, port_name);
			break;
		default:
			printf(", unexpected command %u\n", databuf[3]);
			continue;
		}

		print_simple_payload(&databuf[12]);
		shared_ptr<forward_list<RxpkObject>> pRes = parse_simple_payload(&databuf[12]);
		if(pRes)
		{
			int i = 0;
			for(auto it = pRes->begin(); it != pRes->end(); it++)
			{
				i++;
				char phypayload_decoded[PHYPAYLOAD_BUFSIZE];
				size_t phypayload_decoded_size;
				/* Base64 Decode the PHYPayload */
				rc = mbedtls_base64_decode(phypayload_decoded,
										   sizeof(phypayload_decoded),
										   &phypayload_decoded_size,
										   (const char *)it->base64data,
										   strlen((unsigned char *)it->base64data));
				/* Map the payload to the PhyPayload Struct */
				phypayload_parse(&phy_payload, phypayload_decoded, phypayload_decoded_size);
				/* Decrypt the FRMPayload of the PhyPayload */
				decrypt_frmpayload(&phy_payload, default_AppSKey);
				printf("OBJECT %d DECRYPTED PAYLOAD: %s\n", i, phy_payload.MACPayload.FRMPayload);
			}
			printf("PROCESSED %d OBJECTS IN RXPK ARRAY\n", i);
		}







		/* add some artificial latency */
		usleep(30000); /* 30 ms */

		/* send acknowledge and check return value */
		databuf[3] = ack_command;
		byte_nb = sendto(sock, (void *)databuf, 4, 0, (struct sockaddr *)&dist_addr, addr_len);
		if (byte_nb == -1) {
			printf(", send error:%s\n", strerror(errno));
		} else {
			printf(", %i bytes sent\n", byte_nb);
		}
	}
}
