# binaric_vuln
# Бинарные уязвимости

Урок 2. Видеоурок 1 - Базовые знания
Используя программу prog3 из видео 0х01.04, изменить порядок печати данных из стека и кучи в консоль в процессе выполнения программы, используя отладчик gdb для модификации памяти.

Сейчас:
```cmd
$ ./prog3 
HelloFromStack, HelloFromHeap - 1, 2, 3
Должно быть:

$ gdb -q prog3
...
(gdb) continue
Continuing.
HelloFromHeap, HelloFromStack - 1, 2, 3
```

### Урок 4. Видеоурок 2 - Переполнение стека
Разработать эксплойт, который бы содержал шелл-код с полезной нагрузкой для программы prog4a. Обязательно убедиться в работоспособности шелл-кода (шелл-код будет предоставлен).

```C
$ cat prog4a.c
#include <stdio.h>
#include <string.h>

void vuln_func(char *data) { 
  char buff[256]; 
  strcpy(buff, data); 
} 
void main(int argc, char *argv[]) {
  vuln_func(argv[1]);
} 
$ cat mkdir_shell.str 
\x31\xc0\x50\x68\x54\x45\x53\x54\xb0\x27\x89\xe3\x66\x41\xcd\x80\xb0\x0f\x66\xb9\xff\x01\xcd\x80\x31\xc0\x40\xcd\x80\xb0\x01\x31\xdb\xcd\x80
```

```CMD
$ objdump -D -M intel mkdir_shell | grep -A16 "<shellcode>"
0804a040 <shellcode>:
  804a040:  31 c0                   xor     eax,eax
  804a042:  50                          push    eax
  804a043:  68 54 45 53 54          push    0x54534554
  804a048:  b0 27                   mov     al,0x27
  804a04a:  89 e3                   mov     ebx,esp
  804a04c:  66 41                   inc     cx
  804a04e:  cd 80                   int     0x80
  804a050:  b0 0f                   mov     al,0xf
  804a052:  66 b9 ff 01             mov     cx,0x1ff
  804a056:  cd 80                   int     0x80
  804a058:  31 c0                   xor     eax,eax
  804a05a:  40                          inc     eax
  804a05b:  cd 80                   int     0x80
  804a05d:  b0 01                   mov     al,0x1
  804a05f:  31 db                   xor     ebx,ebx
  804a061:  cd 80                   int     0x80
    ...
```

### Урок 5. Видеоурок 3 - Переполнение кучи
Разработать эксплойт, который бы содержал шелл-код с полезной нагрузкой для программы prog5 из видео 0х03.02. Обязательно убедиться в работоспособности шелл-кода (шелл-код будет предоставлен).

```CMD
$ cat mkdir_shell.str
\x31\xc0\x50\x68\x54\x45\x53\x54\xb0\x27\x89\xe3\x66\x41\xcd\x80\xb0\x0f\x66\xb9\xff\x01\xcd\x80\x31\xc0\x40\xcd\x80\xb0\x01\x31\xdb\xcd\x80


$ objdump -D -M intel mkdir_shell | grep -A16 "<shellcode>"
0804a040 <shellcode>:
804a040: 31 c0 xor eax,eax
804a042: 50 push eax
804a043: 68 54 45 53 54 push 0x54534554
804a048: b0 27 mov al,0x27
804a04a: 89 e3 mov ebx,esp
804a04c: 66 41 inc cx
804a04e: cd 80 int 0x80
804a050: b0 0f mov al,0xf
804a052: 66 b9 ff 01 mov cx,0x1ff
804a056: cd 80 int 0x80
804a058: 31 c0 xor eax,eax
804a05a: 40 inc eax
804a05b: cd 80 int 0x80
804a05d: b0 01 mov al,0x1
804a05f: 31 db xor ebx,ebx
804a061: cd 80 int 0x80
```

### Урок 6. Видеоурок 4 - Уязвимость форматной строки
Используя программу prog6c, записать в переменную test следующие значения: 0x06070809 и 0x77665544.


### Урок 7. Видеоурок 5 - Целочисленное переполнение
Найти уязвимость в программе и разработать эксплойт, который бы позволил вызвать функцию system_priv(), которая по легенде предоставляет доступ к системе с наивысшими привилегиями. Функция была доступна при разработке программы и сейчас содержится в ytq, но для релизной версии разработчик решил, что пользователи не должны иметь к ней доступ и добавил проверку.

```C
$ cat prog12b.c 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
struct data {
  char pass[8];
  int user_id;
  int (*get_shell)(unsigned short int, char *);
};
void user_priv(void);
void admin_priv(void);
void system_priv(void);
void get_shell(unsigned short int, char *);

void get_shell(unsigned short int user_id, char *pass) {
  if (user_id == 128) {
    system_priv();
  }
    ```

    ```  
  if (user_id == 256 && !strcmp("qwerty", pass)) {
    user_priv();
  }
 if (user_id == 512 && !strcmp("asdfgh", pass)) {
    admin_priv();
  }
}
void user_priv(void) {
  printf("ACCESS GRANTED. You have shell with USER privileges.\n");
}
void admin_priv(void) {
 printf("ACCESS GRANTED. You have shell with ADMIN privileges.\n");
}
void system_priv(void) {
  printf("ACCESS GRANTED. You have shell with SYSTEM privileges.\n");
}
og
void main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("USAGE: ./prog12 <user_id> <password>\n");
    return;
  }
  if (atoi(argv[1]) < 256) {
    printf("ERROR: user id must be more than 256.\n");
    return;
  }
  struct data *auth;
  auth = malloc(sizeof(struct data));

  auth->user_id = atoi(argv[1]);
  auth->get_shell = get_shell;
  strcpy(auth->pass, argv[2]);    

  auth->get_shell(auth->user_id, auth->pass);

  free(auth);
}
```

### Урок 9. Видеоурок 6 "Атака возврата в библиотеку"
Для эксплойта, который был разработан в видео 0х06.04, сформировать новую ROP-цепочку на основе динамической библиотеки libc, которая бы печатала в консоль число 13. Утилита ROPgadget может быть использована только для получения ROP-гаджетов.


### Урок 10. Видеоурок 7 "Внутреннее устройство шелл-кода"
Сформировать эксплойт для программы prog4d. В качестве полезной нагрузки необходимо использовать шелл-код test_shell4.c.

```C
$ cat prog4d.c 
#include <stdio.h>
#include <string.h>
void vuln_func(char *data) { 
  char buff[128]; 
  strcpy(buff, data); 
} 
void main(int argc, char *argv[]) {
    vuln_func(argv[1]);
}
$ cat ../0x07.03/test_shell4.c 
#include <stdio.h>
#include <string.h>
unsigned char shellcode[]=
"\x31\xc0\xb0\x04\x31\xdb\xb3\x01"
"\x68\x21\x0a\x41\x41\x68\x6f\x72"
"\x6c\x64\x68\x6f\x2c\x20\x57\x68"
"\x48\x65\x6c\x6c\x89\xe1\x31\xd2"
"\xb2\x0e\xcd\x80\x31\xc0\xb0\x01"
"\x31\xdb\xcd\x80";
void main() {
  printf("Shellcode Length: %d\n", strlen(shellcode));
  int (*ret)() = (int(*)())shellcode;
  ret();
```

Урок 11. Видеоурок 8 "Поиск бинарных уязвимостей"
Дана программа prog15. Исходных текстов нет. Известно, что программа принимает на вход текстовый файл и что-то с ним делает. Необходимо найти уязвимость в программе.

```C
$ cat input.data 
A14AnA32AB57BdC43CZD11DE89EPFF
```
