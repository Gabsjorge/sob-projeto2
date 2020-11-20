#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/string.h>

#define SIZE_BLOCK 16

static int cifrar(char *buff, int len_buff)
{
	char *key = NULL;
	char *scratchpad = NULL;
	char *msg = NULL;
	char *dados_dpsOp = NULL;
	struct scatterlist op_sg;  
	struct scatterlist scratchpad_sg;
	struct skcipher_request *req = NULL; 
	struct crypto_skcipher *skcipher = NULL;
	int ret = -EFAULT, i;

	pr_info("write_crypt - cifrar: Entrou cifrar...\n");
	
	key = kmalloc(SIZE_BLOCK, GFP_KERNEL);
	for(i = 0; i < SIZE_BLOCK; i++) 
	{
		key[i] = 'X';
	}
	skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);

   	if (IS_ERR(skcipher)){
		pr_info("cifrar: Could not allocate skcipher handle!\n");
    	return PTR_ERR(skcipher);

	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("cifrar: Could not allocate skcipher request!\n");
		ret = -ENOMEM;
		goto out;
	}

	if (crypto_skcipher_setkey(skcipher, key, SIZE_BLOCK)) { 
		pr_info("write_crypt - cifrar: Key could not be set!\n");
		ret = -EAGAIN;
		goto out;
	}

	scratchpad = kmalloc(len_buff, GFP_KERNEL);
	msg = kmalloc(len_buff, GFP_KERNEL);
	
	if (!scratchpad || !msg) {
		pr_info("write_crypt - cifrar: Could not allocate scratchpad or msg!\n");
		goto out;
	}
	
	for(i = 0; i < len_buff;i++)
	{
		scratchpad[i] = buff[i];
	}
	
	sg_init_one(&scratchpad_sg, scratchpad, len_buff);
	sg_init_one(&op_sg, msg, len_buff);
	
	skcipher_request_set_crypt(req, &scratchpad_sg, &op_sg, len_buff,NULL);
	
	ret = crypto_skcipher_encrypt(req);
	
	if(ret){
		pr_info("write_crypt - cifrar: cifrar falhou!\n");
		goto out;
	}
	else
	{
		pr_info("write_crypt - cifrar: cifrou com sucesso!\n");
	}	
	
	dados_dpsOp = sg_virt(&op_sg); 

	for(i = 0; i < len_buff;i++)
	{
	 	buff[i] = dados_dpsOp[i];
	}
	
	pr_info("write_crypt - cifrar: Terminou...\n");
	
	out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (scratchpad)
		kfree(scratchpad);
	if (key)
		kfree(key);
	if (msg)
		kfree(msg);


	return ret;
}

asmlinkage ssize_t write_crypt(int fd, const void *buff, size_t nbytes)
{
	int i, num_blocos, len;	
	int tam = nbytes;
	int fd_aux = fd;
	char * buf;
	ssize_t ret;
	mm_segment_t oldfs;

	if(tam % SIZE_BLOCK) 
	{
		num_blocos = 1 + (tam / SIZE_BLOCK);
	}
	else 
	{
		num_blocos = (tam / SIZE_BLOCK); 
	}

	len = num_blocos * SIZE_BLOCK;
	buf = kmalloc(len, GFP_KERNEL);
	
	for(i = 0; i < len; i++)
	{
		if(i < tam) 
		{
			sprintf(&buf[i], "%c", ((char *)buff)[i]);
		}
		else 
		{
			buf[i] = 0;
		}
	}


	pr_info("write_crypt: buf = %s\n", buf);
	pr_info("write_crypt: tam = %d\n", tam);
	pr_info("write_crypt: fd_aux = %d\n", fd_aux);

	if(cifrar(buf, len))
	{
		kfree(buf);
		pr_info("write_crypt: cifrar falhou!\n");
		return -1; 
	}
	
	
	oldfs = get_fs(); /* save previous value */
	set_fs(KERNEL_DS); /* use kernel limit */
	ret = sys_write(fd_aux, buf, len); /* system calls can be invoked */
    	set_fs(oldfs); /* restore before returning to user space */

	/*
	set_fs() 1 is an internal Linux function that is used to override the definition 
	of the user/kernel split, for the current process. 		
	After a set_fs(KERNEL_DS) , no checking is performed that user pointers point to 
	userspace – access_ok will always return true.
	*/

   	kfree(buf);

	pr_info("write_crypt: finalizado com sucesso!\n");

	return ret;
}

