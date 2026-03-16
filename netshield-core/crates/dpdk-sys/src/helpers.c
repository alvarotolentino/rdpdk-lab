/*
 * C shim functions for DPDK macros and static inlines that cannot be
 * called directly from Rust FFI.  Every DPDK interaction goes through
 * these thin wrappers so the Rust side only needs simple extern "C"
 * declarations with primitive types.
 */

#include <string.h>
#include <stdint.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

/* Global mempool — created once during port init */
static struct rte_mempool *g_mbuf_pool = NULL;

/* ---------- port management ---------- */

uint16_t netshield_port_count(void)
{
    return rte_eth_dev_count_avail();
}

int netshield_init_port(uint16_t port_id,
                        uint16_t nb_rx_desc,
                        uint32_t mempool_size,
                        uint32_t cache_size)
{
    struct rte_eth_conf port_conf;
    int ret;

    /* Create the packet mbuf pool (once) */
    if (!g_mbuf_pool) {
        g_mbuf_pool = rte_pktmbuf_pool_create(
            "NETSHIELD_MBUF_POOL",
            mempool_size,
            cache_size,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_socket_id());
        if (!g_mbuf_pool)
            return -1;
    }

    memset(&port_conf, 0, sizeof(port_conf));

    ret = rte_eth_dev_configure(port_id, 1, 0, &port_conf);
    if (ret < 0)
        return ret;

    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rx_desc,
                                 rte_socket_id(), NULL, g_mbuf_pool);
    if (ret < 0)
        return ret;

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        return ret;

    (void)rte_eth_promiscuous_enable(port_id);
    return 0;
}

void netshield_stop_port(uint16_t port_id)
{
    (void)rte_eth_dev_stop(port_id);
}

/* ---------- packet reception ---------- */

uint16_t netshield_rx_burst(uint16_t port_id,
                            uint16_t queue_id,
                            void    **rx_pkts,
                            uint16_t  nb_pkts)
{
    return rte_eth_rx_burst(port_id, queue_id,
                            (struct rte_mbuf **)rx_pkts, nb_pkts);
}

/* ---------- mbuf accessors ---------- */

const uint8_t *netshield_pkt_data(void *mbuf)
{
    return rte_pktmbuf_mtod((struct rte_mbuf *)mbuf, const uint8_t *);
}

uint16_t netshield_pkt_len(const void *mbuf)
{
    return rte_pktmbuf_data_len((const struct rte_mbuf *)mbuf);
}

void netshield_pkt_free(void *mbuf)
{
    rte_pktmbuf_free((struct rte_mbuf *)mbuf);
}
