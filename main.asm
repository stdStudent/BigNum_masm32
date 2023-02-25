.686
.model flat, stdcall
option casemap:none

include c:\masm32\include\msvcrt.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\user32.inc
include c:\masm32\include\Strings.mac

bignum struct
    chunk_count dword    ?  ; число чанков (с dowrd'ами) в массиве buf   
    sign        dword    ?  ; флаг знака (sign = 0 - полож., sign = 1 - отриц.)   
    buf         dword    ?  ; указатель на массив с большим числом
bignum ends

; большое число - массив dword 
; buf[0] - dword, buf[1] - dword, ..., buf[i] - dword
; 13782|AFC53268|493FFFD4
; buf[0] = 493FFFD4
; buf[1] = AFC53268
; buf[2] = 13782

;ДЗ
; 1. + и -
; 2. 
.data


.data?
 
 
.const
new_line db 13,10,0
format_hex db "%08X", 0
format_hex_first db "%X", 0
minus db "-", 0


.code
; выделяет память под массив dword'ов buf размера chunk_count 
; и заполняет структуру большого числа
bignum_init_null proc c uses edi ecx, bn: ptr bignum, chunk_count: dword
    mov edi, [bn]               ; помещаем в edi указатель на структуру большого числа
    assume edi:ptr bignum
    mov ecx, [chunk_count]
    mov [edi].chunk_count, ecx  ; инициализируем поле chunk_count
    mov [edi].sign, 0           ; инициализируем поле sign
    imul ecx, 4
    invoke crt_malloc, ecx      ; выделяем память под массив размера 4*chunk_count
    mov [edi].buf, eax          ; инициализируем поле buf
    
    ret
bignum_init_null endp


;Инициализируем беззнаковое большое число
bignum_set_ui proc c uses edi esi, bn: ptr bignum, number: dword
    invoke bignum_init_null, [bn], 1
	
	;bn->buf[0] = number
	mov edi, [bn]
	assume edi:ptr bignum
	
	mov eax, [number]
	mov esi, [edi].buf
	mov [esi], eax
	
    ret
bignum_set_ui endp


bignum_set_i proc c uses edi esi, bn: ptr bignum, number: dword
    invoke bignum_init_null, [bn], 1
	
	;bn->buf[0] = number
	mov edi, [bn]
	assume edi:ptr bignum
	
	mov eax, [number]
	
	mov ecx, eax
	shr ecx, 31
	.if ecx == 1
		mov [edi].sign, 1
		mov esi, [edi].buf
		neg eax
		mov [esi], eax
	.else	
		mov esi, [edi].buf
		mov [esi], eax
	.endif
    ret
bignum_set_i endp


lastN proc c uses esi edi ecx, s: dword, n:dword
	; return (char*)str + len - n вернёт посление n символов
	invoke crt_strlen, s ; eax - кол-во символов
	.if eax <= [n]
		mov eax, [s]
		ret
	.endif
	
    mov esi, s
    mov edi, n
    add esi, eax
    sub esi, edi
    
    mov eax, esi
    ret
lastN endp

bignum_set_str proc c uses edi esi , bn: ptr bignum, string: dword
    local i: dword
    local sign: byte
    mov [sign], 0
    mov [i], 0             ; 
	
	;bn->buf[0] = number
	mov edi, [bn]
	assume edi:ptr bignum
	
	mov esi, string
    ; проверяем знак
    mov cl, byte ptr [esi]
    .if cl == "-"
		mov [sign], 1
		add esi, 1
    .endif
    
    ;посчитать кол-во символов, разделить на 8 и округлить в большую сторону
	;в цикле с первого чанка a_to_h 
    
    invoke crt_strlen, esi ; eax - кол-во символов
    mov ecx, eax    ; сохранили длину строки
    mov ebx, 8      ; делитель
    xor edx, edx
    div ebx         ; eax/ebx -> eax
    .if edx != 0    ; если есть остаток
		add eax, 1  ; округляем в большую сторону
    .endif
    mov ebx, eax    ; сохранили кол-во чанков
    
    invoke bignum_init_null, [bn], eax
    .if [sign] != 0
		mov [edi].sign, 1
    .endif
    
    
    xor eax, eax
    mov edi, [edi].buf
    .while [i] < ebx
		invoke lastN, esi, 8 ; последние 8 поместил в eax
		push ecx
		invoke crt_strtoul, eax, 0, 16 ; str to hex -> eax
			;mov ebx, eax
			;invoke crt_sscanf, ebx, format_hex, eax
		pop ecx
		.if ecx >= 8
		sub ecx, 8
		.endif
		
		push eax
			push ecx
			imul ecx, 4
			add ecx, 4  ; for '\0'
			invoke crt_malloc, ecx
			pop ecx
		push ecx
		invoke crt_memcpy, eax, esi, ecx ; отрезали последние 8 символов
		pop ecx
		mov esi, eax
		mov byte ptr [esi+ecx], 0 ; добавили \0 str[strlen] = '\0'
		pop eax
		
		;shr esi, 8
		.if [i] != 0
			add edi, 4
		.endif
		;push esi
			;mov esi, [edi].buf
			mov dword ptr [edi], eax
		;pop esi
		inc [i]
    .endw
    
    ret
bignum_set_str endp



bignum_print proc c bn: ptr bignum
     ; for(int i = bn.chunk_count-1; i >= 0; --i)
    ;     printf(format_hex, bn.buf[i]);

    local i: dword

    mov edi, [bn]
    assume edi: ptr bignum
    mov ecx, [edi].chunk_count
    mov [i], ecx                  ; i = bn.chunk_count
    ;dec [i]                       ; --i

	; выводим сначала "-", если число отрицательное
	mov esi, [edi].sign
	.if esi == 1
		invoke crt_printf, addr minus
	.endif

	; первый чанк без незначащих нулей
	mov esi, [edi].buf
    mov edx, [i] ; сохранили i
	dec edx
    imul edx, 4  ; работаем с байтами
    add esi, edx ; смещение до чанка
    invoke crt_printf, addr format_hex_first, dword ptr [esi]
    dec [i]


	; выводим само число
    .while [i] > 0  ; работаем тем, что внутри
        mov esi, [edi].buf
        mov edx, [i] ; сохранили i
		dec edx
        imul edx, 4  ; работаем с байтами
        add esi, edx ; смещение до чанка
        invoke crt_printf, addr format_hex, dword ptr [esi]
        dec [i]
    .endw
    
    invoke crt_printf, addr new_line
    
    ret
bignum_print endp


bignum_and proc c uses edi esi ebx, res: ptr bignum, arg1: ptr bignum, arg2: ptr bignum
    local min_size: dword
    
    mov edi, [arg1]
    assume edi: ptr bignum
    mov esi, [arg2]
    assume esi: ptr bignum
    
    mov eax, [edi].chunk_count
    mov ecx, [esi].chunk_count
    
    .if eax < ecx
		xchg eax, ecx
    .endif
    mov [min_size], ecx
    
    invoke bignum_init_null, [res], ecx
    mov ebx, [res]
    assume ebx: ptr bignum
    
    .if [edi].sign == 1
		.if [esi].sign == 1
			mov [ebx].sign, 1
		.endif
    .endif
    
    mov edi, [edi].buf
    mov esi, [esi].buf
    mov ebx, [ebx].buf
    .while [min_size] > 0 ; беззнаковое, всегда >= 0, нужно просто > 0
		dec [min_size]
		mov eax, dword ptr [edi]
		and eax, dword ptr [esi] ; -> to eax
		mov dword ptr [ebx], eax
		add edi, 4
		add esi, 4
		add ebx, 4
    .endw
    
    ret
bignum_and endp

bignum_realloc proc c uses edi esi ecx, bn: ptr bignum, new_chunk_size: dword
    local old_sz: dword
    
    mov edi, [bn]
    assume edi: ptr bignum
    
    mov ecx, [edi].chunk_count
    mov [old_sz], ecx           ; запомнили старый размер
    
    mov ecx, [new_chunk_size]
    mov [edi].chunk_count, ecx  ; запомнили новый размер
    imul ecx, 4
    
    mov esi, [edi].buf 
    invoke crt_realloc, esi, ecx
    mov [edi].buf, eax          ; перевыделили новый буфер
    
    mov esi, eax
    mov ecx, [old_sz]
    imul ecx, 4
    add esi, ecx       ; добрались до конца старого буфера
    
    ; чистим мусок
    mov ecx, [old_sz]
    .while ecx < [edi].chunk_count
		mov dword ptr [esi], 0
		inc ecx
		add esi, 4 ; next chunk
    .endw
    
	ret ; eax
bignum_realloc endp


;   13782|AFC53268|493FFFD4
; +                12345678
;   13782|AFC53268|5B74564C

bignum_add_i proc c uses edi esi, bn: ptr bignum, num: dword, pos: dword
	local sz: dword
	
	; без переполнения
	mov edi, [bn]
    assume edi: ptr bignum
    
    mov ecx, [edi].chunk_count
    mov [sz], ecx
    
    mov esi, [edi].buf
    mov ecx, [pos]
    imul ecx, 4
    add esi, ecx
    
    mov eax, [num]
    add dword ptr [esi], eax
    
    ; проверяем переполнение
    .while CARRY?
		mov ecx, [sz]
		inc [pos]
		.if [pos] == ecx
			inc ecx
			invoke bignum_realloc, edi, ecx
			mov esi, eax
			mov ecx, [sz]   ; указывает на buf[0], нужно указать на buf[last]
			imul ecx, 4
			add esi, ecx
			sub esi, 4      ; чтобы не указыал за границы буффера
		.endif
		
		add esi, 4
		add dword ptr [esi], 1
    .endw
    
	ret
bignum_add_i endp


bignum_add proc c res: ptr bignum, arg1: ptr bignum, arg2: ptr bignum
    
    ret
bignum_add endp

; proc sub_i

bignum_sub proc c res: ptr bignum, arg1: ptr bignum, arg2: ptr bignum
    
    ret
bignum_sub endp


bignum_mul_ui proc c res: ptr bignum, arg1: ptr bignum, arg2: dword
    
    ret
bignum_mul_ui endp


main proc c argc:DWORD, argv:DWORD, envp:DWORD
    local bn1:bignum
    local bn2:bignum
    local res:bignum
	
	invoke bignum_set_str, addr bn1, $CTA0("ffffffffffffffffffffffff")
	;invoke bignum_set_str, addr bn2, $CTA0("45111111111111111123")
	invoke bignum_set_i, addr bn2, 123456h
	invoke bignum_print, addr bn1
	invoke bignum_print, addr bn2
	
	invoke bignum_add_i, addr bn1, 1h, 0
	invoke bignum_print, addr bn1
	
    mov eax, 0
    ret
main endp

end
