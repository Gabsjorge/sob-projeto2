#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include<stdlib.h>
#include<fcntl.h>
#include<unistd.h>
#include <stdio_ext.h>
#include <string.h>
#include <sys/stat.h>

#define TAM_MAX_MSG 500

void main()
{
	
	struct stat fd_st;
	char arquivo[100], *msg, *msgAntes;	
	int opcao, i, retorno, status;
	int tamArq, tamMsg, fd;

	system("clear");
	printf("--------------------------------------MENU--------------------------------------\n");
	printf("Digite o caminho mais o nome do arquivo:\n");
	printf("  Exemplo: /home/usuario/Área de Trabalho/arq.txt\n\n");
	printf("> ");
	__fpurge(stdin);
	scanf("%[^\n]%*c", arquivo);

	do
	{		
		do{
			system("clear");
			printf("--------------------------------------MENU--------------------------------------\n");
			printf("Arquivo: %s\n\n", arquivo);
			printf("Opcoes:\n");
			printf("1 - Escrever no arquivo\n");
			printf("2 - Ler arquivo\n");
			printf("3 - Apagar o arquivo\n");
			printf("4 - Sair\n");
			printf("\n> ");
			scanf("%d", &opcao);
		}while(opcao < 1 || opcao > 4);
		__fpurge(stdin);
		
		
		switch (opcao)
		{
			case 1: //escrever no arquivo

				//printf("ENTROU 1\n\n ");
				//getchar();

				fd = open(arquivo, O_RDWR | O_CREAT | O_APPEND, 0666);
				if(fd == -1) 
					break;

				/*else
					printf("\nsucesso ao abrir o arq: op 1\n\n ");
				getchar();*/
			
				stat(arquivo, &fd_st);
				tamArq = fd_st.st_size;

				if(tamArq > 0){
					msgAntes = malloc(tamArq);
					retorno = syscall(334, fd, msgAntes, tamArq);

					if(retorno == -1){
						printf("Erro ao abrir o arquivo!");
						if(msgAntes) free(msgAntes);
						getchar();
						break;
					}

				}

				msg = malloc(TAM_MAX_MSG);

				//printf("\nmsg sendo crifrada 1\n\n ");
				//getchar();

				system("clear");
				printf("Digite a mensagem a ser escrita e cifrada no arquivo com no maximo 500 caracteres:\n\n");
				printf("> ");

				if(msgAntes) 
					for(i = 0; i < retorno; i++) 
						if(msgAntes[i] != '\0') printf("%c", msgAntes[i]);

				scanf("%[^\n]", msg);

				tamMsg = strlen(msg);

				if(tamMsg > TAM_MAX_MSG) 
				{
					tamMsg = TAM_MAX_MSG;
					__fpurge(stdin);
				}

				retorno = syscall(335, fd, msg, tamMsg);

				if(retorno) 
				{	
					printf("\nMensagem cifrada com sucesso!\n");					
				}
				else 
				{
					printf("\nErro ao cifrar mensagem!\n");
				}
				getchar();

				if(msg) free(msg);
				if(msgAntes) free(msgAntes);

				close(fd);
				getchar();

				//exebicao
				msgAntes = NULL;
				msg = NULL;

				fd = open(arquivo, O_RDWR | O_CREAT | O_APPEND, 0666);
				if(fd == -1) 
					break;

				stat(arquivo, &fd_st);
				tamArq = fd_st.st_size;

				if(tamArq <= 0){
					printf("Erro: Arquivo vazio!\n");
					getchar();
					break;
				}

				msg = malloc(tamArq);

				retorno = read(fd, msg, tamArq);

				if(retorno == -1){
					printf("Erro: Não foi possível ler o arquivo!\n");
					if(msg) free(msg);
					getchar();
					break;
				}

				printf("\nMensagem cifrada: ");
				for(i = 0; i < retorno; i++) 
					printf("%c", msg[i]);

				if(msg) free(msg);

				close(fd);
				getchar();

				break;

			case 2: //ler decifrado

				fd = open(arquivo, O_RDONLY, 0666);
				if(fd == -1) 
					break;

				stat(arquivo, &fd_st);
				tamArq = fd_st.st_size;

				if(tamArq <= 0){
					printf("Erro: Arquivo vazio!\n");
					getchar();
					break;
				}

				msg = malloc(tamArq);

				retorno = syscall(334, fd, msg, tamArq);

				if(retorno == -1){
					printf("Erro: Não foi possível ler o arquivo!\n");
					if(msg) free(msg);
					getchar();
					break;
				}

				system("clear");
				printf("\nMensagem: ");
				for(i = 0; i < retorno; i++) {
					if(msg[i] != '\0')
						printf("%c", msg[i]);
				}
				printf("\n\nPressione qualquer tecla para continuar ...");

				if(msg) free(msg);
				close(fd);
				getchar();
				break;

			case 3: //apagar arquivo

				status = remove(arquivo);

				system("clear");

				if(!status) 
					printf("Arquivo apagado com sucesso!\n");
				else 
					printf("Erro: Não foi possivel apagar o arquivo!\n");

				getchar();
				break;

			case 4: //sair
				break;
			
		}

		msgAntes = NULL;
		msg = NULL;

	}while(opcao != 4);


}
