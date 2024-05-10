#ifndef SWITCH_NODE_H
#define SWITCH_NODE_H

#include <unordered_map>
#include <ns3/node.h>
#include "qbb-net-device.h"
#include "switch-mmu.h"
#include "pint.h"


namespace ns3 {

class Packet;

class SwitchNode : public Node{
	static const uint32_t timesketch_array_num = 3;
	static const uint32_t switch_num = 64;
	static const uint32_t qlenU = 320;
	static const uint32_t pCnt = 16;	// Number of ports used
	static const uint32_t qCnt = 8;	// Number of queues/priorities used、
	static const uint32_t qlen_scale = 1024; // qlen scale per 100Gbps
	static const uint32_t coco_len = 64;	// len of coco_every_100Gbps
	static const uint32_t time_len = 512;	// len of timesketch_every_100Gbps
	static const uint32_t scale_mon = 8;	// scale of monitor
	static const uint32_t tx_scale = 1000;	// scale of txmonitor
	static const uint32_t delay_scale = 128;	// scale of qtime per_100Gbps
	static const uint32_t delay_scale_mon = 16384;	// scale of qtime
	static const uint32_t coco_window_num = 4;	// scale of qtime
	static const uint32_t cache_len = coco_len;

	int32_t b_rtt[switch_num][switch_num];
	uint32_t m_ecmpSeed;
	std::unordered_map<uint32_t, std::vector<int> > m_rtTable; // map from ip address (u32) to possible ECMP port (index of dev)

	// monitor of PFC
	uint32_t m_bytes[pCnt][pCnt][qCnt]; // m_bytes[inDev][outDev][qidx] is the bytes from inDev enqueued for outDev at qidx
	uint64_t m_ackpointer[pCnt];
	uint64_t m_txBytes[pCnt]; // counter of tx bytes
	uint32_t m_lastPktSize[pCnt];
	uint64_t m_lastPktTs[pCnt]; // ns
	uint64_t m_lastPktTs1[pCnt]; // ns
	uint32_t m_lastoldPktSize[pCnt];
	uint64_t m_delay[pCnt][delay_scale_mon];
	uint64_t m_delay_time[pCnt][delay_scale_mon];
	uint64_t m_basetxtime[pCnt];
	double m_u[pCnt];
	double m_first_RTT_rate[pCnt];
	uint64_t lasttimesketch[pCnt][timesketch_array_num][time_len*20];
	uint64_t firsttimesketch[pCnt][timesketch_array_num][time_len*20];
	uint32_t coco_id[pCnt][coco_window_num][coco_len*20];
	uint32_t coco_freq[pCnt][coco_window_num][coco_len*20];
	uint32_t coco_ts[pCnt][coco_window_num][coco_len*20];

	uint32_t cache_id[pCnt][cache_len * 20];
	uint32_t cache_freq[pCnt][cache_len * 20];
	uint32_t cache_pointer_head[pCnt];
	uint32_t cache_pointer_tail[pCnt];
protected:
	bool m_ecnEnabled;
	uint32_t m_ccMode;
	uint64_t m_maxRtt;

	uint32_t m_ackHighPrio; // set high priority for ACK/NACK

private:
	int GetOutDev(Ptr<const Packet>, CustomHeader &ch);
	void SendToDev(Ptr<Packet>p, CustomHeader &ch);
	static uint32_t EcmpHash(const uint8_t* key, size_t len, uint32_t seed);
	void CheckAndSendPfc(uint32_t inDev, uint32_t qIndex);
	void CheckAndSendResume(uint32_t inDev, uint32_t qIndex);
public:
	Ptr<SwitchMmu> m_mmu;

	static TypeId GetTypeId (void);
	SwitchNode();
	void SetEcmpSeed(uint32_t seed);
	void AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx);
	void ClearTable();
	bool SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch);
	void SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p);

	// for approximate calc in PINT
	int logres_shift(int b, int l);
	int log2apprx(int x, int b, int m, int l); // given x of at most b bits, use most significant m bits of x, calc the result in l bits
};

} /* namespace ns3 */

#endif /* SWITCH_NODE_H */
