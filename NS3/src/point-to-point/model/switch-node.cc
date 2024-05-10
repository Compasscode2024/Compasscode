#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/pause-header.h"
#include "ns3/flow-id-tag.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "switch-node.h"
#include "qbb-net-device.h"
#include "ppp-header.h"
#include "ns3/int-header.h"
#include <cmath>

namespace ns3 {

TypeId SwitchNode::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SwitchNode")
    .SetParent<Node> ()
    .AddConstructor<SwitchNode> ()
	.AddAttribute("EcnEnabled",
			"Enable ECN marking.",
			BooleanValue(false),
			MakeBooleanAccessor(&SwitchNode::m_ecnEnabled),
			MakeBooleanChecker())
	.AddAttribute("CcMode",
			"CC mode.",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ccMode),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("AckHighPrio",
			"Set high priority for ACK/NACK or not",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ackHighPrio),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("MaxRtt",
			"Max Rtt of the network",
			UintegerValue(9000),
			MakeUintegerAccessor(&SwitchNode::m_maxRtt),
			MakeUintegerChecker<uint32_t>())
  ;
  return tid;
}

SwitchNode::SwitchNode(){
	m_ecmpSeed = m_id;
	m_node_type = 1;
	m_mmu = CreateObject<SwitchMmu>();
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++)
			for (uint32_t k = 0; k < qCnt; k++)
				m_bytes[i][j][k] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_txBytes[i]= 0;


	if (m_id >= 80 && m_id <= 83)
	{
		for (uint32_t i = 0; i < pCnt; i++)
			m_basetxtime[i] = 3000;
	}
	else if (m_id >=72 && m_id <= 79)
	{
		for (uint32_t i = 0; i < 3; i++)
			m_basetxtime[i] = 4000;
		for (uint32_t i = 3; i < pCnt; i++)
			m_basetxtime[i] = 2000;
	}
	else if (m_id >=64 && m_id <= 71)
	{
		for (uint32_t i = 0; i < 3; i++)
			m_basetxtime[i] = 1000;
		for (uint32_t i = 3; i < pCnt; i++)
			m_basetxtime[i] = 5000;
	}
	for (int i = 0; i < switch_num; i++)
		for (int j = 0; j<switch_num; j++)
		{
			if ((i < 32 && j >=32)||(i >= 32 && j <32))
			b_rtt[i][j] = 0;
			else if ((i/8) == (j/8))
			b_rtt[i][j] = 8000;
			else
			b_rtt[i][j] = 4000;
		}

	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < delay_scale_mon; j++)
		m_delay[i][j] = m_delay_time[i][j] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_lastoldPktSize[i] = m_lastPktSize[i] = m_lastPktTs[i] = m_lastPktTs1[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_u[i] = m_first_RTT_rate[i] = 0;
	for (int k = 0; k < pCnt; k++)
	for (uint32_t i = 0; i < timesketch_array_num; i++)
		for (uint32_t j = 0; j < time_len * 20; j++)
		lasttimesketch[k][i][j] = firsttimesketch[k][i][j] = 0;
	for (uint32_t j = 0; j < pCnt; j++)
	for (uint32_t k = 0; k < coco_window_num; k++)
	for (uint32_t i = 0; i < coco_len * 20; i++)
		coco_id[j][k][i] = coco_freq[j][k][i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
	{
		cache_pointer_head[i] = cache_pointer_tail[i] = 0;
		for (uint32_t j = 0; j < cache_len*20; j++)
			cache_id[i][j] = cache_freq[i][j] = 0;
	}
}

int SwitchNode::GetOutDev(Ptr<const Packet> p, CustomHeader &ch){
	// look up entries
	auto entry = m_rtTable.find(ch.dip);

	// no matching entry
	if (entry == m_rtTable.end())
		return -1;

	// entry found
	auto &nexthops = entry->second;

	// pick one next hop based on hash
	union {
		uint8_t u8[4+4+2+2];
		uint32_t u32[3];
	} buf;
	buf.u32[0] = ch.sip;
	buf.u32[1] = ch.dip;
	if (ch.l3Prot == 0x6)
		buf.u32[2] = ch.tcp.sport | ((uint32_t)ch.tcp.dport << 16);
	else if (ch.l3Prot == 0x11)
		buf.u32[2] = ch.udp.sport | ((uint32_t)ch.udp.dport << 16);
	else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)
		buf.u32[2] = ch.ack.sport | ((uint32_t)ch.ack.dport << 16);

	uint32_t idx = EcmpHash(buf.u8, 12, m_ecmpSeed) % nexthops.size();
	return nexthops[idx];
}

void SwitchNode::CheckAndSendPfc(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldPause(inDev, qIndex)){
		device->SendPfc(qIndex, 0);
		m_mmu->SetPause(inDev, qIndex);
	}
}
void SwitchNode::CheckAndSendResume(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldResume(inDev, qIndex)){
		device->SendPfc(qIndex, 1);
		m_mmu->SetResume(inDev, qIndex);
	}
}

void SwitchNode::SendToDev(Ptr<Packet>p, CustomHeader &ch){
	int ifIndex = GetOutDev(p, ch);
	if (ifIndex >= 0){
		NS_ASSERT_MSG(m_devices[ifIndex]->IsLinkUp(), "The routing table look up should return link that is up");

		// determine the qIndex
		uint32_t qIndex;
		if (ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0;
		}else{
			qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
		}

		// admission control
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();
		if (qIndex != 0){ //not highest priority
			if (m_mmu->CheckIngressAdmission(inDev, qIndex, p->GetSize()) && m_mmu->CheckEgressAdmission(ifIndex, qIndex, p->GetSize())){			// Admission control
				m_mmu->UpdateIngressAdmission(inDev, qIndex, p->GetSize());
				m_mmu->UpdateEgressAdmission(ifIndex, qIndex, p->GetSize());
			}else{
				return; // Drop
			}
			CheckAndSendPfc(inDev, qIndex);
		}
		m_bytes[inDev][ifIndex][qIndex] += p->GetSize();
		//insert here

		if (m_ccMode == 3 || m_ccMode == 11){ // HPCC or powertcp
		uint32_t tp;
		uint8_t* bufbuf = p->GetBuffer();
		uint64_t now_t = Simulator::Now().GetTimeStep();
		union {
		uint8_t u8[4+4+2+2];
		uint32_t u32[3];
		} buf;
		uint32_t ifack;
		uint32_t idxx[3];
		uint32_t id_in_coco;
		uint32_t index_in_coco;
		uint32_t coco_win_pointer;
		uint32_t window_scale = m_maxRtt;
		uint32_t pktlen;
		uint32_t coco_win_pointer_up;
		uint32_t inc = 0;
		if (bufbuf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
				tp = ifIndex;
				pktlen = p->GetSize();
				ifack = 0;
				buf.u32[0] = ch.sip;
				buf.u32[1] = ch.dip;
				if (ch.l3Prot == 0x6)
					buf.u32[2] = ch.tcp.sport | ((uint32_t)ch.tcp.dport << 16);
				else if (ch.l3Prot == 0x11)
					buf.u32[2] = ch.udp.sport | ((uint32_t)ch.udp.dport << 16);
				else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)
					buf.u32[2] = ch.ack.sport | ((uint32_t)ch.ack.dport << 16);

		}
		else
		{
			ifack = 1;
			pktlen = 0;
			tp = inDev;
		}
		
			Ptr<QbbNetDevice> dev_used = DynamicCast<QbbNetDevice>(m_devices[tp]);
			uint32_t used_coco_len = coco_len * (dev_used->GetDataRate().GetBitRate()/100000000000);
			uint32_t used_time_len = time_len* (dev_used->GetDataRate().GetBitRate()/100000000000);
			uint32_t used_cache_len = cache_len* (dev_used->GetDataRate().GetBitRate()/100000000000);
			coco_win_pointer = (now_t - 2000000000) / window_scale;
			coco_win_pointer = coco_win_pointer % coco_window_num;
			if (now_t <= 2000000000 + 2 * window_scale)
			{
				coco_win_pointer_up = 0;
			}
			else
			{
				coco_win_pointer_up = (now_t - 2000000000 - 2 * window_scale ) / window_scale;
				coco_win_pointer_up = (((coco_win_pointer_up % coco_window_num) + 1) * used_coco_len )% (used_coco_len * coco_window_num);
			}
			if (ifack == 0)
			{	
				uint32_t srcip = (ch.sip>>8)&63;
				uint32_t dstip = (ch.dip>>8)&63;
				id_in_coco = EcmpHash(buf.u8, 12, m_ecmpSeed - 10);
				id_in_coco = id_in_coco & 0xfffffffc;
				uint32_t tag = 0;
				
				if (b_rtt[srcip][dstip] == 0)
				tag = 0;
				else if (b_rtt[srcip][dstip] == 4000)
				tag = 1;
				else if (b_rtt[srcip][dstip] == 8000)
				tag = 2;
				id_in_coco = id_in_coco | tag;

				index_in_coco = EcmpHash(buf.u8, 12, m_ecmpSeed + 10) % used_coco_len;
				
			}

			uint32_t* osize_ary;
			uint32_t* oid_ary;
			uint32_t inc_step = used_coco_len;
			uint32_t o_num = 0;
			if (ifack == 0)
			{
				coco_freq[tp][coco_win_pointer][index_in_coco] += pktlen;
				double rd = (double)(rand())/(double)(RAND_MAX);
				double prb = (double)(pktlen)/(double)(coco_freq[tp][coco_win_pointer][index_in_coco]);
				if (prb > rd)
				{
					coco_id[tp][coco_win_pointer][index_in_coco] = id_in_coco;
				}
			}
			else
			{

				if (coco_win_pointer_up != m_ackpointer[tp])
				{

					inc = 1;
					osize_ary = new uint32_t[used_coco_len];
					oid_ary = new uint32_t[used_coco_len];
					for (int i = 0; i < inc_step; i++)
                       			{
                                		osize_ary[i] = oid_ary[i] = 0;
                       			 }

					for (int i = 0; i <inc_step; i++)
					{
						index_in_coco = m_ackpointer[tp] % used_coco_len;
						coco_win_pointer = m_ackpointer[tp] / used_coco_len;
						coco_win_pointer = coco_win_pointer % coco_window_num;
						osize_ary[i] = coco_freq[tp][coco_win_pointer][index_in_coco];
						oid_ary[i] = coco_id[tp][coco_win_pointer][index_in_coco];
						if (coco_freq[tp][coco_win_pointer][index_in_coco] != 0)
							o_num++;
						coco_freq[tp][coco_win_pointer][index_in_coco] = 0;
						coco_id[tp][coco_win_pointer][index_in_coco] = 0;
						m_ackpointer[tp] = (m_ackpointer[tp] + 1) %(coco_window_num * used_coco_len);
					}
				}
			}
			
			uint32_t oid = 0;
			uint32_t osize = 0;

			if (ifack == 1)
			{
				//std::cout<<"onum:"<<o_num<<std::endl;
				if (o_num == 0)
				{
						osize = cache_freq[tp][cache_pointer_head[tp]% used_cache_len];
						oid = cache_id[tp][cache_pointer_head[tp]% used_cache_len];
						cache_freq[tp][cache_pointer_head[tp]% used_cache_len] = 0;
						cache_id[tp][cache_pointer_head[tp]% used_cache_len] = 0;
						cache_pointer_head[tp] = cache_pointer_head[tp] + 1;
						if (cache_pointer_head[tp] - 1 == cache_pointer_tail[tp])
							cache_pointer_tail[tp] += 1;
						
				}
			
				else
				{
					for (int i = 0; i <inc_step; i++)
					{
						if (osize_ary[i] != 0)
						{
							osize = osize_ary[i];
							oid = oid_ary[i];
							osize_ary[i] = 0;
							oid_ary[i] = 0;
							o_num--;
							break;
						}
					}
					if (o_num >0)
					{
						

						if (cache_pointer_tail[tp] - cache_pointer_head[tp] <= used_cache_len - o_num)
						{
							for (int i = 0; i <inc_step; i++)
							{
								if (osize_ary[i] != 0)
								{
									cache_pointer_tail[tp]++;
									cache_freq[tp][cache_pointer_tail[tp]% used_cache_len] = osize_ary[i];
									cache_id[tp][cache_pointer_tail[tp]% used_cache_len] = oid_ary[i];
								}
							}
						}
						else
						{
							std::cout<<"why!"<<std::endl;
							for (int i = 0; i <inc_step; i++)
							{
								if (osize_ary[i] != 0)
								{
									uint32_t cache_index = EcmpHash((uint8_t*)&oid_ary[i], 4, m_ecmpSeed + 15) % used_cache_len;
			
									cache_freq[tp][cache_index] += osize_ary[i];
									double rd = (double)(rand())/(double)(RAND_MAX);
									double prb = (double)(osize_ary[i])/(double)(cache_freq[tp][cache_index]);
									if (prb > rd)
									{
										cache_id[tp][cache_index] = oid_ary[i];
									}
								}
							}
							
						}


					}
				}
			}
			
				uint64_t deltatime = 0;  
				uint64_t lasttime = now_t;
				uint64_t firsttime = now_t;
				//current time
				if (ifack == 0)
				{
					for (uint32_t i = 0 ; i < 3; i++)
					{
						idxx[i] = EcmpHash((uint8_t*)&id_in_coco, 4, m_ecmpSeed + i * 1000) % used_time_len;
						if (now_t - lasttimesketch[tp][i][idxx[i]] > deltatime)
						deltatime = now_t - lasttimesketch[tp][i][idxx[i]];

						lasttimesketch[tp][i][idxx[i]] = now_t;
					}

					
					for (uint32_t i = 0 ; i < 3; i++)
					{
						idxx[i] = EcmpHash((uint8_t*)&id_in_coco, 4, m_ecmpSeed + i * 1000) % used_time_len;
						
						if (deltatime > 4 * m_maxRtt || firsttimesketch[i][idxx[i]] == 0)
						firsttimesketch[tp][i][idxx[i]] = now_t;
					}
				}
				else if (osize > 0)
				{
					for (uint32_t i = 0 ; i < 3; i++)
					{
						idxx[i] = EcmpHash((uint8_t*)&oid, 4, m_ecmpSeed + i * 1000) % used_time_len;
						if (lasttime > lasttimesketch[tp][i][idxx[i]])
							lasttime = lasttimesketch[tp][i][idxx[i]];
					}

					
					for (uint32_t i = 0 ; i < 3; i++)
					{
						idxx[i] = EcmpHash((uint8_t*)&oid, 4, m_ecmpSeed + i * 1000) % used_time_len;
						if (firsttime > firsttimesketch[tp][i][idxx[i]])
							firsttime = firsttimesketch[tp][i][idxx[i]];
					}
					//std::cout<<"lastfirsttime:"<<lasttime<<" "<<firsttime<<std::endl;
					uint32_t taag = oid&3;
					if (lasttime - firsttime > m_maxRtt - taag * 4000)
					osize = 0;
				}
			if (inc ==1)
			{
				delete[] oid_ary;
				delete[] osize_ary;
			}
			if (ifack == 1)
			{
				if (inc == 1)
				{	
					double first_RTT_rate = double(m_lastoldPktSize[tp]) / double(window_scale) * 8 * 1e9;
					double weight_ewma = double(1) / double(scale_mon);
					m_first_RTT_rate[tp] = m_first_RTT_rate[tp] * (1 - weight_ewma) + first_RTT_rate * weight_ewma;
					m_lastoldPktSize[tp] = 0;
				}
				m_lastoldPktSize[tp] += osize;
				
			}
			// if (m_id == 7 && tp == 4)
			// {
			// 	std::cout<<"interest: "<<coco_win_pointer_up<<" "<<tp<<" "<<m_ackpointer[tp]<<std::endl;
			// }
		}
		//
		m_devices[ifIndex]->SwitchSend(qIndex, p, ch);
	}else
		return; // Drop
}

uint32_t SwitchNode::EcmpHash(const uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  if (len > 3) {
    const uint32_t* key_x4 = (const uint32_t*) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h += (h << 2) + 0xe6546b64;
    } while (--i);
    key = (const uint8_t*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

void SwitchNode::SetEcmpSeed(uint32_t seed){
	m_ecmpSeed = seed;
}

void SwitchNode::AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx){
	uint32_t dip = dstAddr.Get();
	m_rtTable[dip].push_back(intf_idx);
}

void SwitchNode::ClearTable(){
	m_rtTable.clear();
}

// This function can only be called in switch mode
bool SwitchNode::SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch){
	SendToDev(packet, ch);
	return true;
}

void SwitchNode::SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){
	Ptr<QbbNetDevice> dev1 = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
	uint64_t qdelay = Simulator::Now().GetTimeStep() - dev1->GetQueue()->m_packetTimestamps[p];
	dev1->GetQueue()->m_packetTimestamps.erase(p);
	uint64_t used_delay_scale = delay_scale/(dev1->GetDataRate().GetBitRate()/100000000000);
	
	
	
	FlowIdTag t;
	p->PeekPacketTag(t);
	if (qIndex != 0){
		uint32_t inDev = t.GetFlowId();
		m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());
		m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p->GetSize());
		m_bytes[inDev][ifIndex][qIndex] -= p->GetSize();
		if (m_ecnEnabled){
			bool egressCongested = m_mmu->ShouldSendCN(ifIndex, qIndex);
			if (egressCongested){
				PppHeader ppp;
				Ipv4Header h;
				p->RemoveHeader(ppp);
				p->RemoveHeader(h);
				h.SetEcn((Ipv4Header::EcnType)0x03);
				p->AddHeader(h);
				p->AddHeader(ppp);
			}
		}
		//CheckAndSendPfc(inDev, qIndex);
		CheckAndSendResume(inDev, qIndex);
	}
	uint64_t now_t = Simulator::Now().GetTimeStep();
	if (1){
		uint8_t* buf = p->GetBuffer();
		if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
			IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
			Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
			if (m_ccMode == 3 || m_ccMode == 11){ // HPCC
				
				CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
			    p->PeekHeader(ch);
				uint32_t pst_delay_index;
				uint64_t pst_qdelay;
				
				if (now_t + m_basetxtime[ifIndex] - m_maxRtt < 2000000000)
					pst_qdelay = 0;
				else
				{

					pst_delay_index = (now_t + m_basetxtime[ifIndex] - m_maxRtt - 2000000000) /used_delay_scale;
					pst_delay_index = pst_delay_index % delay_scale_mon;
					if (now_t - m_delay_time[ifIndex][pst_delay_index] < m_maxRtt)
					pst_qdelay = m_delay[ifIndex][pst_delay_index];
					else
					pst_qdelay = 0;
				}
				
				uint32_t qlen = dev->GetQueue()->GetNBytesTotal();

				double qlen1 = 0;

				uint32_t qlen2 = qlen;
				
				double fact = 1 -  m_first_RTT_rate[ifIndex]/dev->GetDataRate().GetBitRate() * (1);
				double thresh = 0.05 * m_maxRtt * dev1->GetDataRate().GetBitRate()/8/1e9;
				
				 if (qlen > 0)
				 {
				 	qlen1 = (double)qlen - m_first_RTT_rate[ifIndex] *  (pst_qdelay) / 1e9/8;
				 	if (qlen1 >=0 )
				 	qlen2 = qlen1/fact;
				 	else
				 	{

				 		qlen2 = (1<<16) * qlenU - abs(qlen1) /fact;
				 	}
				 }
				
				

				// if (m_id == 64 && ifIndex == 3)
				//  {
				// 	// std::cout<<m_first_RTT_rate[ifIndex]<<std::endl;
				// 	if ( Simulator::Now().GetTimeStep() >= 2001013031 && Simulator::Now().GetTimeStep() < 2001013031 + 2000000)
				// 	std::cout<<(double)(Simulator::Now().GetTimeStep()- 2001013031)/(double)1e6<<" "<<qlen/(double)(1024)<<std::endl;
				// }

				ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes[ifIndex], qlen2, dev->GetDataRate().GetBitRate());
				
				
				


			}


			else if (m_ccMode == 10){ // HPCC-PINT
				uint64_t t = Simulator::Now().GetTimeStep();
				uint64_t dt = t - m_lastPktTs[ifIndex];
				if (dt > m_maxRtt)
					dt = m_maxRtt;
				uint64_t B = dev->GetDataRate().GetBitRate() / 8; //Bps
				uint64_t qlen = dev->GetQueue()->GetNBytesTotal();
				double newU;

				/**************************
				 * approximate calc
				 *************************/
				int b = 20, m = 16, l = 20; // see log2apprx's paremeters
				int sft = logres_shift(b,l);
				double fct = 1<<sft; // (multiplication factor corresponding to sft)
				double log_T = log2(m_maxRtt)*fct; // log2(T)*fct
				double log_B = log2(B)*fct; // log2(B)*fct
				double log_1e9 = log2(1e9)*fct; // log2(1e9)*fct
				double qterm = 0;
				double byteTerm = 0;
				double uTerm = 0;
				if ((qlen >> 8) > 0){
					int log_dt = log2apprx(dt, b, m, l); // ~log2(dt)*fct
					int log_qlen = log2apprx(qlen >> 8, b, m, l); // ~log2(qlen / 256)*fct
					qterm = pow(2, (
								log_dt + log_qlen + log_1e9 - log_B - 2*log_T
								)/fct
							) * 256;
					// 2^((log2(dt)*fct+log2(qlen/256)*fct+log2(1e9)*fct-log2(B)*fct-2*log2(T)*fct)/fct)*256 ~= dt*qlen*1e9/(B*T^2)
				}
				if (m_lastPktSize[ifIndex] > 0){
					int byte = m_lastPktSize[ifIndex];
					int log_byte = log2apprx(byte, b, m, l);
					byteTerm = pow(2, (
								log_byte + log_1e9 - log_B - log_T
								)/fct
							);
					// 2^((log2(byte)*fct+log2(1e9)*fct-log2(B)*fct-log2(T)*fct)/fct) ~= byte*1e9 / (B*T)
				}
				if (m_maxRtt > dt && m_u[ifIndex] > 0){
					int log_T_dt = log2apprx(m_maxRtt - dt, b, m, l); // ~log2(T-dt)*fct
					int log_u = log2apprx(int(round(m_u[ifIndex] * 8192)), b, m, l); // ~log2(u*512)*fct
					uTerm = pow(2, (
								log_T_dt + log_u - log_T
								)/fct
							) / 8192;
					// 2^((log2(T-dt)*fct+log2(u*512)*fct-log2(T)*fct)/fct)/512 = (T-dt)*u/T
				}
				newU = qterm+byteTerm+uTerm;

				#if 0
				/**************************
				 * accurate calc
				 *************************/
				double weight_ewma = double(dt) / m_maxRtt;
				double u;
				if (m_lastPktSize[ifIndex] == 0)
					u = 0;
				else{
					double txRate = m_lastPktSize[ifIndex] / double(dt); // B/ns
					u = (qlen / m_maxRtt + txRate) * 1e9 / B;
				}
				newU = m_u[ifIndex] * (1 - weight_ewma) + u * weight_ewma;
				printf(" %lf\n", newU);
				#endif

				/************************
				 * update PINT header
				 ***********************/
				uint16_t power = Pint::encode_u(newU);
				if (power > ih->GetPower())
					ih->SetPower(power);

				m_u[ifIndex] = newU;
			}
		}
	}
	


	uint32_t cur_delay_index = (now_t - 2000000000) / used_delay_scale;
	cur_delay_index = cur_delay_index %delay_scale_mon;
	m_delay[ifIndex][cur_delay_index] = qdelay;
	m_delay_time[ifIndex][cur_delay_index] = now_t;
	
	uint64_t dt = Simulator::Now().GetTimeStep() - m_lastPktTs1[ifIndex];
	if (dt > tx_scale)
	{
		double txRate = double(m_lastPktSize[ifIndex]) / double(dt) * 8 * 1e9;
		m_lastPktSize[ifIndex] = 0;
		m_lastPktTs1[ifIndex] = Simulator::Now().GetTimeStep();
		// if (m_id == 64 && ifIndex == 3)
		// if ( Simulator::Now().GetTimeStep() >= 2001013031 && Simulator::Now().GetTimeStep() < 2001013031 + 2000000)
		// std::cout<<(double)(Simulator::Now().GetTimeStep()- 2001013031)/(double)1e6<<" "<<txRate/1e9<<std::endl;
	}

	m_txBytes[ifIndex] += p->GetSize();
	m_lastPktSize[ifIndex] += p->GetSize();
	m_lastPktTs[ifIndex] = Simulator::Now().GetTimeStep();
}

int SwitchNode::logres_shift(int b, int l){
	static int data[] = {0,0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5};
	return l - data[b];
}

int SwitchNode::log2apprx(int x, int b, int m, int l){
	int x0 = x;
	int msb = int(log2(x)) + 1;
	if (msb > m){
		x = (x >> (msb - m) << (msb - m));
		#if 0
		x += + (1 << (msb - m - 1));
		#else
		int mask = (1 << (msb-m)) - 1;
		if ((x0 & mask) > (rand() & mask))
			x += 1<<(msb-m);
		#endif
	}
	return int(log2(x) * (1<<logres_shift(b, l)));
}

} /* namespace ns3 */
