#ifndef SRC_PACKET_FWD_PROTOCOL_H_
#define SRC_PACKET_FWD_PROTOCOL_H_

#include <forward_list>
#include <memory>

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

void packet_fwd_print_payload(char * payload);
/**
 * Parse the payload of the simple protocol defined by the Packet Forwarder.
 *
 * @param payload	Pointer to buffer containing the root JSON object. This object is
 * 					found in the UDP datagrams sent by the packet forwarder
 * @return	On success, a pointer to a list of RxpkObjects.
 * 			On failure, returns a null pointer.
 */
std::shared_ptr<std::forward_list<RxpkObject>> packet_fwd_parse_payload(const char *payload);




#endif /* SRC_PACKET_FWD_PROTOCOL_H_ */
