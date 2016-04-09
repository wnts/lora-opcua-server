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

#include <stdint.h>		/* C99 types */
#include <stdio.h>		/* printf, fprintf, sprintf, fopen, fputs */
#include <unistd.h>		/* usleep */

#include <string.h>		/* memset */
#include <time.h>		/* time, clock_gettime, strftime, gmtime, clock_nanosleep*/
#include <stdlib.h>		/* atoi, exit */
#include <errno.h>		/* error messages */

#include <sys/socket.h> /* socket specific definitions */
#include <netinet/in.h> /* INET constants and stuff */
#include <arpa/inet.h>  /* IP address conversion stuff */
#include <netdb.h>		/* gai_strerror */

#include "parson.h"		/* JSON parsing */
#include <base64.h>		/* mbed TLS for decoding base64 */
#include <aes.h>		/* for decryping the FRMPayload */

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

#define PAYLOAD_DATA_BUF_SIZE 512

static const unsigned char default_AppSKey[] = {
		0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
		0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

typedef struct {
	unsigned char MHDR;
	unsigned char DevAddr[4];
	unsigned char FCtrl;
	unsigned char FCnt[2];
	unsigned char FOpts[15];
	unsigned char FHDR[23];
	unsigned char FPort;
	unsigned char FRMPayload[250]; /* Maximum allowed for Datarate 7 */
	unsigned char MIC[4];
} PhyPayload;

void print_payload(char * payload)
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

void process_payload(const char *payload, char *time, char *data, size_t *size)
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

	*size = 0;
	*data = '\0';
	*time = '\0';

	MSG("\nProcessing Payload\n");

	/* parsing json and validating output */
	payload_root_value = json_parse_string(payload);
	if (json_value_get_type(payload_root_value) != JSONObject) {
		MSG("Error: payload root value is not a JSONObject\n");
		json_value_free(payload_root_value);
		return;
	}

	payload_identifier_object = json_value_get_object(payload_root_value);
	if (json_object_get_count(payload_identifier_object) != 1) {
		MSG("Error: payload identifier cannot be determined");
		json_value_free(payload_root_value);
		return;
	}
	/* Ignore status payloads */
	if (strcmp(json_object_get_name(payload_identifier_object, 0), "stat") == 0) {
		json_value_free(payload_root_value);
		return;
	}
	if (strcmp(json_object_get_name(payload_identifier_object, 0), "rxpk") == 1) {
		MSG("Error: payload identifier unkown");
		json_value_free(payload_root_value);
		return;
	}

	payload_identifier_value = json_object_get_value(
			payload_identifier_object,
			json_object_get_name(payload_identifier_object, 0));
	if (json_value_get_type(payload_identifier_value) != JSONArray) {
		MSG("Error: payload identifier value is not a JSONArray\n");
		json_value_free(payload_root_value);
		return;
	}

	payload_content_array = json_value_get_array(payload_identifier_value);
	for (i = 0; i < json_array_get_count(payload_content_array); i++) {
		payload_content_object = json_array_get_object(payload_content_array, i);

		*size = (size_t)json_object_get_number(payload_content_object, "size");
		data_string = json_object_get_string(payload_content_object, "data");
		time_string = json_object_get_string(payload_content_object, "time");

		strcpy(data, data_string);
		strcpy(time, time_string);

		MSG("%s data:\"%s\" (%d bytes)\n", time, data, *size);
	}

	/* cleanup code */
	json_value_free(payload_root_value);
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
	uint8_t databuf[4096];
	int byte_nb;

	/* variables for protocol management */
	uint32_t raw_mac_h; /* Most Significant Nibble, network order */
	uint32_t raw_mac_l; /* Least Significant Nibble, network order */
	uint64_t gw_mac; /* MAC address of the client (gateway) */
	uint8_t ack_command;

	/* variables for receiving payloads */
	size_t payload_size_encoded;
	size_t payload_size_decoded;

	unsigned char payload_data_encoded[PAYLOAD_DATA_BUF_SIZE];
	unsigned char payload_data_decoded[PAYLOAD_DATA_BUF_SIZE];
	unsigned char payload_timestamp[32];

	PhyPayload phy_payload;
	size_t FOptsLen;
	size_t FRMPayloadLen;

	mbedtls_aes_context aes_ctx;
	size_t aes_offset = 0;
	unsigned char aes_nonce_counter[16];
	unsigned char aes_stream_block[16];
	unsigned char FRMPayload_decrypted[250];

	int rc;

	/* check if port number was passed as parameter */
	if (argc != 2) {
		MSG("Usage: util_ack <port number>\n");
		exit(EXIT_FAILURE);
	}

	/* prepare AES */
	mbedtls_aes_init(&aes_ctx);
	mbedtls_aes_setkey_enc(&aes_ctx, default_AppSKey, 128);

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

		print_payload(&databuf[12]);

		/* Get the encoded PHYPayload from the data field */
		process_payload(&databuf[12], payload_timestamp, payload_data_encoded, &payload_size_encoded);

		/* Base64 Decode the PHYPayload */
		if (payload_size_encoded > 0) {
			rc = mbedtls_base64_decode(payload_data_decoded, PAYLOAD_DATA_BUF_SIZE, &payload_size_decoded,
					payload_data_encoded, strlen(payload_data_encoded));
			MSG("base64 decode return: %d\n", rc);
			MSG("payload encoded size: %d decoded size: %d\n", payload_size_encoded, payload_size_decoded);
			/*MSG("complete decoded payload:\n");
			for (i=0;i<payload_size_decoded;i++) {
				printf("0x%02x ", payload_data_decoded[i]);
				if (i%16 == 0 && i>0) { printf("\n"); }
			}
			MSG("\n");*/

			/* Map the payload to the PhyPayload Struct */
			memset(&phy_payload, 0, sizeof(PhyPayload));

			memcpy(&phy_payload.MHDR, payload_data_decoded, 1);
			MSG("MHDR=0x%x\n", phy_payload.MHDR);

			memcpy(phy_payload.DevAddr, payload_data_decoded + 1, 4);
			MSG("DevAddr=%02x:%02x:%02x:%02x\n", phy_payload.DevAddr[0], phy_payload.DevAddr[1],
					phy_payload.DevAddr[2], phy_payload.DevAddr[3]);

			memcpy(&phy_payload.FCtrl, payload_data_decoded+5, 1);
			MSG("FCtrl=0x%x\n", phy_payload.FCtrl);

			memcpy(&phy_payload.FCnt, payload_data_decoded+6, 2);
			MSG("FCnt=%d\n", (uint16_t)(*phy_payload.FCnt));

			FOptsLen = (size_t)(phy_payload.FCtrl && 0x3);
			printf("foptslen:%d\n", FOptsLen);

			memcpy(phy_payload.FOpts, payload_data_decoded+8, FOptsLen);
			memcpy(&phy_payload.FPort, payload_data_decoded+8+FOptsLen, 1);
			MSG("FPort=%d\n", phy_payload.FPort);

			FRMPayloadLen = (size_t) ((payload_data_decoded+payload_size_decoded-4) /* address of end of frame - MIC */
					- (payload_data_decoded+9+FOptsLen));                           /* address of beginning of FRMPayLoad */
			printf("frmpayloadlen:%d\n", FRMPayloadLen);

			memcpy(phy_payload.FRMPayload, payload_data_decoded+9+FOptsLen, FRMPayloadLen);
			memcpy(phy_payload.MIC, payload_data_decoded+payload_size_decoded-4, 4);
			MSG("MIC=0x%x%x%x%x\n", phy_payload.MIC[0], phy_payload.MIC[1], phy_payload.MIC[2], phy_payload.MIC[3]);

/*
			printf("frmpayload encrypted:\n");
			for (i=0;i<FRMPayloadLen;i++) {
				printf("0x%02x ", phy_payload.FRMPayload[i]);
				if (i%16 == 0 && i>0) { printf("\n"); }
			}*/




			/* Construct counter for using CTR mode on AES
			 * The format of the counter is specified in the LoraWan specification
			 * WARNING: the nonce counter is a 16-byte number stored in little-endian format
			 * 			any of its (multi-byte) subfields are also little-endian
			 * */
			aes_offset = 0;
			memset(aes_stream_block, 0, 16);
			memset(aes_nonce_counter, 0, 16);
			aes_nonce_counter[0] = 0x01;	// hard-coded constant from spec
			// aes_nonce_counter[1-4] == 0 already from memset
			aes_nonce_counter[5] = 0; 		// Uplink frame = 0
			// aes_nonce_counter[6-9] = DevAddr
			memcpy(&aes_nonce_counter[6], phy_payload.DevAddr, sizeof(phy_payload.DevAddr));
			// FCnt field is zero extended to 32 bits
			aes_nonce_counter[10] = phy_payload.FCnt[0];
			aes_nonce_counter[11] = phy_payload.FCnt[1];
			aes_nonce_counter[12] = 0x00;
			aes_nonce_counter[13] = 0x00;
			//aes_nonce_counter[14] == 0 already from memset
			// actual "counter" that is incremented in CTR mode for every 16-byte block
			aes_nonce_counter[15] = 1;

			/* Decrypt the FRMPayload using the known AES key */
			rc = mbedtls_aes_crypt_ctr(&aes_ctx,
					FRMPayloadLen,
					&aes_offset,
					aes_nonce_counter,
					aes_stream_block,
					phy_payload.FRMPayload,
					FRMPayload_decrypted);
			printf("\nrc from aes:%d\n", rc);
			printf("offset after aes:%d\n", aes_offset);
			printf("frmpayload decrypted:\n");
			/*
			for (i=0;i<FRMPayloadLen;i++) {
				printf("0x%02x ", FRMPayload_decrypted[i]);
				printf("%c", FRMPayload_decrypted[i]);
				if (i%16 == 0 && i>0) { printf("\n");}
			}*/
			printf("\n");
			// make sure it's null-terminated
			FRMPayload_decrypted[FRMPayloadLen] = '\0';
			printf("Plain decrypted result: %s\n", FRMPayload_decrypted);
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
