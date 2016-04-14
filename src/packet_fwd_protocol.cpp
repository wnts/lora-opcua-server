#include <string.h>
#include <forward_list>
#include <memory>

#include "parson.h"
#include "packet_fwd_protocol.h"

#define MSG(args...)	fprintf(stderr, args) /* message that is destined to the user */

using namespace std;

void packet_fwd_print_payload(char * payload)
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

shared_ptr<forward_list<RxpkObject>> packet_fwd_parse_payload(const char *payload)
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
