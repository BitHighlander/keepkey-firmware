
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include "wallet/wallet2.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "serialization/binary_archive.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-vault-v11-agent-1/modules/keepkey-firmware/tools/monero-feasibility/commands/core-signing.h"
template<class T>T pod(const uint8_t *p){T v;memcpy(&v,p,32);return v;}
template<class T>std::string dump(T &v){std::ostringstream stream;binary_archive<true> ar(stream);if(!::serialization::serialize(ar,v))throw std::runtime_error("serialize");return stream.str();}
std::string hex(const std::string &v){return epee::string_tools::buff_to_hex_nodelimer(v);}
int main(int argc,char **argv){
 el::Configurations logging;logging.setToDefault();logging.setGlobally(el::ConfigurationType::Enabled,"false");logging.setGlobally(el::ConfigurationType::ToFile,"false");logging.setGlobally(el::ConfigurationType::ToStandardOutput,"false");el::Loggers::setDefaultConfigurations(logging,true);el::Loggers::reconfigureAllLoggers(logging);
 monero_core_plan plan{};std::ifstream f(argv[1],std::ios::binary);f.read((char*)&plan,sizeof(plan));if(!f)throw std::runtime_error("fixture plan");
 std::string viewhex;std::cin>>viewhex;crypto::secret_key view;if(!epee::string_tools::hex_to_pod(viewhex,view))throw std::runtime_error("view");
 cryptonote::address_parse_info info;if(!cryptonote::get_account_address_from_str(info,cryptonote::MAINNET,plan.destinations[1].address))throw std::runtime_error("address");
 tools::wallet2 wallet(cryptonote::MAINNET,1,true);wallet.set_subaddress_lookahead(1,1);wallet.generate("",epee::wipeable_string(),info.address,view,false);
 std::tuple<uint64_t,uint64_t,std::vector<tools::wallet2::exported_transfer_details>> outputs;std::get<0>(outputs)=0;std::get<1>(outputs)=plan.input_count;
 tools::wallet2::tx_construction_data cd{};cd.use_rct=true;cd.use_view_tags=true;cd.rct_config={rct::RangeProofPaddedBulletproof,4};
 for(unsigned n=0;n<plan.input_count;++n){const auto &in=plan.sources[n];tools::wallet2::exported_transfer_details entry{};entry.m_pubkey=pod<crypto::public_key>(in.ring[in.real_member].public_key);entry.m_internal_output_index=in.output_index;entry.m_global_output_index=in.ring[in.real_member].global_index;entry.m_tx_pubkey=pod<crypto::public_key>(in.tx_public_key);entry.m_amount=in.amount;entry.m_flags.m_rct=true;entry.m_subaddr_index_major=in.subaddress_major;entry.m_subaddr_index_minor=in.subaddress_minor;for(unsigned k=0;k<in.additional_key_count;++k)entry.m_additional_tx_keys.push_back(pod<crypto::public_key>(in.additional_tx_public_keys[k]));std::get<2>(outputs).push_back(entry);
 cryptonote::tx_source_entry src{};src.real_output=in.real_member;src.real_output_in_tx_index=in.output_index;src.real_out_tx_key=entry.m_tx_pubkey;src.real_out_additional_tx_keys=entry.m_additional_tx_keys;src.amount=in.amount;src.rct=true;src.mask=pod<rct::key>(in.mask);for(const auto &ring:in.ring)src.outputs.push_back({ring.global_index,{pod<rct::key>(ring.public_key),pod<rct::key>(ring.commitment)}});cd.sources.push_back(src);cd.selected_transfers.push_back(plan.input_count-1-n);cd.subaddr_indices.insert(in.subaddress_minor);}
 for(unsigned n=0;n<plan.output_count;++n){const auto &out=plan.destinations[n];cryptonote::address_parse_info dest;if(!cryptonote::get_account_address_from_str(dest,cryptonote::MAINNET,out.address))throw std::runtime_error("dest");cryptonote::tx_destination_entry entry(out.address,out.amount,dest.address,dest.is_subaddress);cd.splitted_dsts.push_back(entry);if(out.is_change)cd.change_dts=entry;else cd.dests.push_back(entry);}
 cryptonote::add_tx_pub_key_to_extra(cd.extra,pod<crypto::public_key>(plan.sources[0].tx_public_key));std::string nonce;cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(nonce,crypto::null_hash8);cryptonote::add_extra_nonce_to_tx_extra(cd.extra,nonce);
 std::string header((const char*)&info.address.m_spend_public_key,32);header.append((const char*)&info.address.m_view_public_key,32);std::string outputbytes=std::string("Monero output export\004")+wallet.encrypt_with_view_secret_key(header+dump(outputs));tools::wallet2::unsigned_tx_set txs;txs.txes.push_back(cd);txs.new_transfers=outputs;std::string unsignedbytes=std::string("Monero unsigned tx set\005")+wallet.encrypt_with_view_secret_key(dump(txs));
 rapidjson::Document reply;reply.SetObject();auto &a=reply.GetAllocator();auto add=[&](const char *k,const std::string &v){reply.AddMember(rapidjson::Value(k,a),rapidjson::Value(v.data(),v.size(),a),a);};add("op","plan");add("address",plan.destinations[1].address);add("view_key",viewhex);add("outputs_data_hex",hex(outputbytes));add("unsigned_txset",hex(unsignedbytes));rapidjson::StringBuffer out;rapidjson::Writer<rapidjson::StringBuffer>w(out);reply.Accept(w);std::cout.write(out.GetString(),out.GetSize());std::cout<<'\n';}
