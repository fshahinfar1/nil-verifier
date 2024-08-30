/* vim: set et ts=2 sw=2: */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/tcp.h>

/* Put state of each socket in this struct (This will be used in sockops.h as
 * part of per socket metadata) */
/* struct connection_state { }; */
/* #include "sockops.h" */

/* SEC("sk_skb/stream_parser") */
/* int parser(struct __sk_buff *skb) */
/* { */
/*   bpf_printk("parser"); */
/*   return skb->len; */
/* } */

/* SEC("sk_skb/stream_verdict") */
/* int verdict(struct __sk_buff *skb) */
/* { */
/*   bpf_printk("here"); */
/*   if (bpf_skb_pull_data(skb, skb->len) != 0) { */
/*     bpf_printk("Parser: Failed to load message data"); */
/*     return SK_DROP; */
/*   } */
/*   void *data = (void *)((__u64)skb->data); */
/*   void *data_end = (void *)((__u64)skb->data_end); */
/*   __u16 len = skb->len; */
/*   bpf_printk("recv: %d bytes", len); */
/*   return (SK_DROP); */
/* } */

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
  bpf_printk("hello");
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
