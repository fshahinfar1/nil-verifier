#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <linux/bpfptr.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/file.h>

#include "nil_verifier.h"

typedef struct {
	struct bpf_prog *prog;
	union bpf_attr *attr;
	bpfptr_t fd_array;
} env_t;


/* Arithmatic and Jump Opcode */
typedef struct {
	u32 cls;
	u32 src;
	u32 code;
} __attribute__((packed)) aj_opcode_t;

/* Load and store opcode */
typedef struct {
	u32 cls;
	u32 sz;
	u32 mode;
} __attribute__((packed)) ls_opcode_t;


static inline void unpack_aj_opcode(u8 opcode, aj_opcode_t *o)
{
	o->cls = opcode & 0x07;
	o->src = (opcode & (0x03 << 3)) >> 3;
	o->code = opcode & 0xf0;
}

static inline void unpack_ls_opcode(u8 opcode, ls_opcode_t *o)
{
	o->cls = opcode & 0x7;
	o->sz = (opcode & 0x8) >> 3;
	o->mode = ((opcode & 0x07) << 5) >> 5;
}

static int __link_funcs(env_t *env)
{
	struct bpf_insn *inst = env->prog->insnsi;
	int inst_cnt = env->prog->len;
	for (int i = 0; i < inst_cnt; i++) {
		aj_opcode_t o;
		/* o.raw = inst[i].code; */
		unpack_aj_opcode(inst[i].code, &o);

		/* printk("%d: %x|%x|%x\n", i, o.cls, o.src, o.code); */
		if ( !(o.cls == BPF_JMP && o.src == BPF_K && o.code == BPF_CALL) ) {
			/* It is not a call instruction */
			continue;
		}
		/* printk("found a func call\n"); */

		if (inst[i].src_reg == 0) {
			/* call helper function by ID */
			return -EINVAL;
		} else if (inst[i].src_reg == 1) {
			/* Function call */
			printk("We do not support function calls\n");
			return -EINVAL;
		} else if (inst[i].src_reg == 3) {
			/* using BTF id for helper functions */
			printk("We are not support BTF\n");
			return -EINVAL;
		} else {
			/* Invalid */
			return -EINVAL;
		}
	}
	return 0;
}

/* static struct bpf_map *__bpf_map_get(struct fd f) */
/* { */
/* 	if (!f.file) */
/* 		return ERR_PTR(-EBADF); */
/* 	if (f.file->f_op != &bpf_map_fops) { */
/* 		fdput(f); */
/* 		return ERR_PTR(-EINVAL); */
/* 	} */

/* 	return f.file->private_data; */
/* } */


static inline int __get_map_fd_from_index(bpfptr_t fd_array, int imm, u32 *fd_ptr)
{
	if (bpfptr_is_null(fd_array)) {
		printk("fd_idx without fd_array is invalid\n");
		return -EPROTO;
	}
	if (copy_from_bpfptr_offset(fd_ptr, fd_array, imm * sizeof(u32), sizeof(u32)))
		return -EFAULT;
	return 0;
}

static inline void __bpf_map_inc(struct bpf_map *map)
{
	atomic64_inc(&map->refcnt);
}


static int __link_maps(env_t *env)
{
	int ret, err;
	struct bpf_insn *inst = env->prog->insnsi;
	int inst_cnt = env->prog->len;
	for (int i = 0; i < inst_cnt; i++) {
		ls_opcode_t o;
		/* o.raw = inst[i].code; */
		unpack_ls_opcode(inst[i].code, &o);

		if (!(o.cls == BPF_LD && o.sz == BPF_IMM && o.mode == BPF_DW))
			continue;

		/* Next instruction should be for data of current insturction */
		if (i == inst_cnt - 1 ||
				inst[i+1].code != 0 ||
				inst[i+1].dst_reg != 0 ||
				inst[i+1].src_reg != 0 ||
				inst[i+1].off != 0) {
			printk("invalid bpf_ld_imm64 insn\n");
			return -EINVAL;
		}


		int src = inst[i].src_reg;
		struct bpf_map *map;
		struct fd f;
		u64 addr;
		u32 fd;

		switch(src) {
			case 0:
				break;
			case 1:
				/* map fd */
				fd = inst[i].imm;
				break;
			case 2:
				/* map fd value */
				fd = inst[i].imm;
				break;
			case 3: /* fallthrough */
			case 4:
				printk("Does not support BTF\n");
				return -EINVAL;
			case 5:
				/* map index */
				ret = __get_map_fd_from_index(env->fd_array, inst[i].imm, &fd);
				if (ret) return ret;
				break;
			case 6:
				/* map index value */
				ret = __get_map_fd_from_index(env->fd_array, inst[i].imm, &fd);
				if (ret) return ret;
				break;
			default:
				return -EINVAL;
		}

		f = fdget(fd);
		map = __bpf_map_get(f);
		if (IS_ERR(map)) {
			printk("fd %d is not pointing to valid bpf_map\n", inst[i].imm);
			return PTR_ERR(map);
		}

		if (src == BPF_PSEUDO_MAP_FD || src == BPF_PSEUDO_MAP_IDX) {
			addr = (unsigned long)map;
		} else {
			u32 off = inst[i].imm;

			if (off >= BPF_MAX_VAR_OFF) {
				printk("direct value offset of %u is not allowed\n", off);
				fdput(f);
				return -EINVAL;
			}

			if (!map->ops->map_direct_value_addr) {
				printk("no direct value access support for this map type\n");
				fdput(f);
				return -EINVAL;
			}

			err = map->ops->map_direct_value_addr(map, &addr, off);
			if (err) {
				printk("invalid access to map value pointer, value_size=%u off=%u\n",
					map->value_size, off);
				fdput(f);
				return err;
			}
		}

		inst[i].imm = (u32)addr;
		inst[i+1].imm = (u32)(addr >> 32);


		/* hold the map. If the program is rejected by verifier,
		 * the map will be released by release_maps() or it
		 * will be used by the valid program until it's unloaded
		 * and all maps are released in bpf_free_used_maps()
		 */
		__bpf_map_inc(map);

		fdput(f);
	}
	return 0;
}

int nil_bpf_check(struct bpf_prog **prog, union bpf_attr *attr, bpfptr_t uattr, __u32 uattr_size)
{
	env_t *env = kzalloc(sizeof(env_t), GFP_KERNEL);

	if (attr->prog_type == BPF_PROG_TYPE_SOCKET_FILTER ||
			attr->prog_type == BPF_PROG_TYPE_TRACEPOINT) {
		return 0;
	}

	if (attr->prog_type != BPF_PROG_TYPE_XDP) {
		printk("Current focus is on XDP programs (%d)\n", attr->prog_type);
		return -EINVAL;
	}

	env->prog = prog[0];
	env->attr = attr;
	env->fd_array = make_bpfptr(attr->fd_array, uattr.is_kernel);

	if (__link_funcs(env)) {
		goto err_free_env;
	}

	if (__link_maps(env)) {
		goto err_free_env;
	}

	/* goto err_free_env; */
	/* Okay */
	printk("Loading XDP program\n");
	return 0;

err_free_env:
	/* Reject the program */
	kfree(env);
	return -EINVAL;
}
