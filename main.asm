.686
.model flat, stdcall
option casemap:none

include c:\masm32\include\msvcrt.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\user32.inc
include c:\masm32\include\Strings.mac

;function1 proto :DWORD, :DWORD

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

.data


.data?
 
 
.const
new_line db 13,10,0
format_hex db "%08X", 0
format_hex_first db "%X", 0
minus db "-", 0
error_str db "Error string!", 0
format_str db "%s", 0


.code
; выдел€ет пам€ть под массив dword'ов buf размера chunk_count 
; и заполн€ет структуру большого числа


bignum_init_null proc c uses edi ecx, bn: ptr bignum, chunk_count: dword
    mov edi, [bn]               ; помещаем в edi указатель на структуру большого числа
    assume edi:ptr bignum
    mov ecx, [chunk_count]
    mov [edi].chunk_count, ecx  ; инициализируем поле chunk_count
    mov [edi].sign, 0           ; инициализируем поле sign
    imul ecx, 4
    invoke crt_malloc, ecx      ; выдел€ем пам€ть под массив размера 4*chunk_count
    mov [edi].buf, eax          ; инициализируем поле buf
    
    ; обнул€ем число
    mov ecx, [edi].chunk_count
    .while ecx > 0
		mov dword ptr [eax], 0
		dec ecx
		add eax, 4 ; next chunk
    .endw
    
    ret
bignum_init_null endp


;»нициализируем беззнаковое большое число
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
	; return (char*)str + len - n вернЄт посление n символов
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

check_str proc c uses esi ebx, string: dword
	local i: dword
	local flag: dword
	
	mov [i], 0
	mov [flag], 0
	
	mov esi, [string]
	mov cl, byte ptr[esi]
	.if cl == "-"
		inc esi
	.endif
	invoke crt_strlen, esi
	mov ecx, eax
	
	.while ecx > 0
		mov edx, [i]
		mov bl, byte ptr[esi + edx]
		.if bl >= 30h
			.if bl <= 39h
				mov [flag], 1
			.endif
		.endif
		
		.if bl >= 41h
			.if bl <= 46h
				mov [flag], 1
			.endif
		.endif
		
		.if bl >= 61h
			.if bl <= 66h
				mov [flag], 1
			.endif
		.endif
		
		.if [flag] == 0
			invoke crt_printf, addr format_str, addr error_str
			invoke crt_exit, -1
		.endif	
		
		mov [flag], 0
		inc [i]
		dec ecx
	.endw
	
	ret
check_str endp

bignum_set_str proc c uses edi esi, bn: ptr bignum, string: dword
    local i: dword
    local sign: byte
    mov [sign], 0
    mov [i], 0             ; 
	
	mov edi, [bn]
	assume edi:ptr bignum
	
	invoke crt_strlen, [string]
	
	mov esi, string
	invoke check_str, [string]
    
    mov cl, byte ptr [esi]
    .if cl == "-"
		mov [sign], 1
		add esi, 1
    .endif
    
    
    invoke crt_strlen, esi 
    mov ecx, eax   
    mov ebx, 8      
    xor edx, edx
    div ebx         
    .if edx != 0    
		add eax, 1  
    .endif
    mov ebx, eax    
    
    invoke bignum_init_null, [bn], eax
    .if [sign] != 0
		mov [edi].sign, 1
    .endif
    
    
    xor eax, eax
    mov edi, [edi].buf
    .while [i] < ebx
		invoke lastN, esi, 8
		push ecx
		invoke crt_strtoul, eax, 0, 16 
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
    local i: dword

    mov edi, [bn]
    assume edi: ptr bignum
    mov ecx, [edi].chunk_count
    mov [i], ecx                  
    
	mov esi, [edi].sign
	.if esi == 1
		invoke crt_printf, $CTA0("-")
	.endif

	mov esi, [edi].buf
    mov edx, [i] 
	dec edx
    imul edx, 4  
    add esi, edx 
    invoke crt_printf, addr format_hex_first, dword ptr [esi]
    dec [i]

    .while [i] > 0  
        mov esi, [edi].buf
        mov edx, [i]
		dec edx
        imul edx, 4  
        add esi, edx 
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
    .while [min_size] > 0
		dec [min_size]
		mov eax, dword ptr [edi]
		and eax, dword ptr [esi]
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
    
    mov ecx, [old_sz]
    .while ecx < [edi].chunk_count
		mov dword ptr [esi], 0
		inc ecx
		add esi, 4 ; next chunk
    .endw
    
	ret ; eax
bignum_realloc endp


bignum_add_i proc c uses edi esi ecx eax, bn: ptr bignum, num: dword, pos: dword
	local sz: dword
	
	; без переполнени€
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
    
    ; провер€ем переполнение
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

; proc sub_i
bignum_sub_i proc c uses edi esi ecx ebx, bn: ptr bignum, num: dword, pos: dword
	local sz: dword
	
	; без переполнени€
	mov edi, [bn]
    assume edi: ptr bignum
    
    mov ecx, [edi].chunk_count
    mov [sz], ecx
    
    mov esi, [edi].buf
    mov ecx, [pos]
    imul ecx, 4
    add esi, ecx
    
    mov eax, [num]
    .if eax > dword ptr [esi]
		mov ebx, dword ptr [esi]
		xchg eax, ebx
		mov dword ptr [esi], ebx
    .endif
    
    sub dword ptr [esi], eax
    
    .if CARRY?
		add esi, 4
		sub dword ptr [esi], 1
    .endif
    
	ret
bignum_sub_i endp

bignum_compare proc c uses esi edi ebx ecx, arg1: ptr bignum, arg2: ptr bignnum
	mov esi, [arg1]
	assume esi: ptr bignum

	mov edi, [arg2]
	assume edi: ptr bignum
	
	mov ecx, [esi].chunk_count
	mov edx, [edi].chunk_count
	mov eax, 0
	.if ecx == edx
		mov ebx, [esi].buf
		mov edx, [edi].buf
		.while ecx > 0
			push eax
			dec ecx
			mov eax, dword ptr[ebx + 4*ecx]
			.if eax > dword ptr[edx + 4*ecx]
				pop eax
				mov eax, 1
				.break
			.elseif eax < dword ptr[edx + 4*ecx]
				pop eax
				mov eax, -1
				.break
			.endif
			pop eax
			inc ecx
			
			dec ecx
		.endw
	.elseif ecx > edx
		mov eax, 1
	.else
		mov eax, -1
	.endif
	ret
bignum_compare endp

bignum_sub proc c uses esi edi ebx, res: ptr bignum, arg1: ptr bignum, arg2: ptr bignum
    local sz:dword
    local count:dword
    local current:dword
    local minus_bool_1:dword
    local minus_bool_2:dword
    local regular_bool:dword
    
    mov [count], 0
    mov [minus_bool_1], 0
    mov [minus_bool_2], 0
    mov [regular_bool], 0
    
    mov esi, [arg1]
    assume esi: ptr bignum
    
    mov ebx, [arg2]
    assume ebx: ptr bignum
    
    .if [esi].sign == 1
		mov [minus_bool_1], 1
		mov [regular_bool], 1
    .endif

	.if [ebx].sign == 1
		mov [minus_bool_2], 1
		mov [regular_bool], 1
	.endif
	
	.if [minus_bool_1] == 1
		.if [minus_bool_2] == 1
			mov [regular_bool], 0
		.endif
	.endif
    
    mov eax, [esi].chunk_count
	.if eax > [ebx].chunk_count
		inc eax
	.else
		mov eax, [ebx].chunk_count
		inc eax
    .endif
    
    invoke bignum_init_null, [res], eax
    mov edi, [res]
    assume edi: ptr bignum
    
    mov ecx, [esi].sign
    mov [edi].sign, ecx
    
    mov eax, [esi].buf
    mov ecx, [esi].chunk_count
    .while ecx > 0
		dec ecx
		invoke bignum_add_i, edi, dword ptr[eax+ 4*ecx], ecx
		inc ecx
		dec ecx
    .endw
    
    mov ecx, [ebx].buf
    mov eax, [ebx].chunk_count
    mov [sz], eax
    .if [regular_bool] == 0
		invoke bignum_compare, [arg1], [arg2]
		.if eax == -1
			.if [edi].sign == 0
				inc [edi].sign
			.else
				dec [edi].sign
			.endif
		.elseif eax == 0
			mov [edi].sign, 0		
		.endif
		.while [sz] > 0
			mov eax, dword ptr [ecx]
			invoke bignum_sub_i, edi, eax, [count]
			
			add ecx, 4
			
			inc [count]
			dec [sz]
		.endw
		
	.else
		.while [sz] > 0
			mov eax, dword ptr [ecx]
			invoke bignum_add_i, edi, eax, [count]
			
			add ecx, 4
			
			inc [count]
			dec [sz]
		.endw
	.endif
	
	mov ecx, [edi].chunk_count
	mov eax, [edi].buf
	xor edx, edx
	.while ecx > 0
		dec ecx
		.if dword ptr[eax+4*ecx] == 0
			.if ecx != 0
				inc edx
			.endif
		.else
			.break		
		.endif
		inc ecx
		dec ecx
	.endw
	
	mov ecx, [edi].chunk_count
	sub ecx, edx
	invoke bignum_realloc, edi, ecx
    
    ret
bignum_sub endp

bignum_add proc c uses edi esi ebx ecx eax, res: ptr bignum, arg1: ptr bignum, arg2: ptr bignum
    local sz:dword
    local count:dword
    local current:dword
    local minus_bool_1:dword
    local minus_bool_2:dword
    local regular_bool:dword
    local sign:dword
    
    mov [count], 0
    mov [minus_bool_1], 0
    mov [minus_bool_2], 0
    mov [regular_bool], 0
    mov [sign], 0
    
    
    mov esi, [arg1]
    assume esi: ptr bignum
    
    mov ebx, [arg2]
    assume ebx: ptr bignum
    
    .if [esi].sign == 1
		mov [minus_bool_1], 1
		mov [regular_bool], 1
    .endif

	.if [ebx].sign == 1
		mov [minus_bool_2], 1
		mov [regular_bool], 1
	.endif
	
	.if [minus_bool_1] == 1
		.if [minus_bool_2] == 1
			mov [sign], 1
			mov [regular_bool], 0
		.endif
	.endif
	
	mov eax, [esi].chunk_count
	.if eax > [ebx].chunk_count
		inc eax
	.else
		mov eax, [ebx].chunk_count
		inc eax
    .endif
    
    invoke bignum_init_null, [res], eax
    mov edi, [res]
    assume edi: ptr bignum
    mov ecx, [esi].sign
    mov [edi].sign, ecx
    
    mov eax, [esi].buf
    mov ecx, [esi].chunk_count
    .while ecx > 0
		dec ecx
		invoke bignum_add_i, edi, dword ptr[eax+ 4*ecx], ecx
		inc ecx
		dec ecx
    .endw	
    
    mov ecx, [ebx].buf
    mov eax, [ebx].chunk_count
    mov [sz], eax
    .if [regular_bool] == 0
		push ecx
		mov ecx, [sign]
		mov [edi].sign, ecx
		pop ecx
		.while [sz] > 0
			mov eax, dword ptr [ecx]
			invoke bignum_add_i, edi, eax, [count]
			
			add ecx, 4
			
			inc [count]
			dec [sz]
		.endw
	.else
		invoke bignum_compare, [arg1], [arg2]
		.if eax == -1
			.if [edi].sign == 0
				inc [edi].sign
			.else
				dec [edi].sign
			.endif
		.elseif eax == 0
			mov [edi].sign, 0	
		.endif
		.while [sz] > 0
			mov eax, dword ptr [ecx]
			invoke bignum_sub_i, edi, eax, [count]
			
			add ecx, 4
			
			inc [count]
			dec [sz]
		.endw
	.endif
	
	mov ecx, [edi].chunk_count
	mov eax, [edi].buf
	xor edx, edx
	.while ecx > 0
		dec ecx
		.if dword ptr[eax+4*ecx] == 0
			.if ecx != 0
				inc edx
			.endif
		.else
			.break	
		.endif
		inc ecx
		dec ecx
	.endw
	
	mov ecx, [edi].chunk_count
	sub ecx, edx
	invoke bignum_realloc, edi, ecx
    
    ret
bignum_add endp

bignum_mul_ui proc c uses edi esi ebx ecx eax edx, res: ptr bignum, arg1: ptr bignum, arg2: dword
    local sz:dword
    local count:dword
    
    mov edi, [res]
    assume edi: ptr bignum
    
    mov esi, [arg1]
    assume esi: ptr bignum
    
    mov ecx, [esi].chunk_count
    inc ecx
    push ecx
    mov ecx, [edi].sign
    .if ecx > 1
		pop ecx
		invoke bignum_init_null, edi, ecx
	.else
		 pop ecx
    .endif
    
    mov ecx, [esi].buf
    mov eax, [esi].chunk_count
    mov ebx, [edi].buf ;result
    mov [sz], eax
    .while [sz] > 0
		mov eax, dword ptr [ecx]
		mul dword ptr [arg2]
		
		add dword ptr [ebx], eax
		add ebx, 4
		add dword ptr [ebx], edx
		add ecx, 4
		
		dec [sz]
	.endw
    
    ret
bignum_mul_ui endp

sum_array proc c uses esi eax ecx edx, b1: ptr bignum, array: dword
	local sz: dword
	local i: dword
	local num: dword
	
	mov [i], 0
	
	mov esi, [b1]
	assume esi: ptr bignum
	mov eax, [array]
	mov ecx, [esi].chunk_count
	mov [sz], ecx
	xor ecx, ecx
	
	.while [sz] > 0
		mov ecx, [i]
		mov edx, dword ptr[eax+ecx*4]
		invoke bignum_add_i, esi, edx, [i]
		
		inc [i]
		dec [sz]
	.endw
	 
	ret
sum_array endp

sdvig proc c uses esi eax ecx edx, bn: ptr bignum
	mov esi, [bn]
	assume esi: ptr bignum
	mov eax, [esi].buf
	mov ecx, [esi].chunk_count
	.while ecx > 0
		dec ecx
		mov edx, dword ptr[eax+4*ecx]
		inc ecx
		mov dword ptr[eax+4*ecx], edx
		dec ecx
	.endw
	mov dword ptr[eax], 000000000h
	mov [esi].buf, eax
	ret
sdvig endp
 
bignum_mul proc c uses esi edi ebx, res: ptr bignum, arg1: ptr bignum, arg2: ptr bignum
	local i:dword
	local sz2: dword
	local tmp_buf: dword
	local szRes: dword
	local num: dword
	local sign: dword
	
	
	mov [i], 0
	
	mov edi, [arg1]
	assume edi: ptr bignum
	
	mov esi, [arg2]
	assume esi: ptr bignum
		
	mov ecx, [esi].chunk_count
	mov [sz2], ecx
	add ecx, [edi].chunk_count
	invoke bignum_init_null, [res], ecx
	mov [szRes], ecx
	imul ecx, 4
	invoke crt_malloc, ecx
	mov [tmp_buf], eax
	mov ebx, [res]
	assume ebx: ptr bignum
	
	mov ecx, 2
	mov eax, [edi].sign
	add eax, [esi].sign
	xor edx, edx
	div ecx
	mov [sign], edx
	
	mov eax, [esi].buf
	.while [sz2] > 0
		push eax		
		.if [i] != 0
			mov eax, [tmp_buf]
			mov ecx, [szRes]
			push ebx
			.while ecx > 0
				dec ecx
				mov dword ptr[eax + ecx*4], 0h
				mov ebx, dword ptr[eax + ecx*4]
				add ebx, dword ptr[edx + ecx*4]
				add dword ptr[eax + ecx*4], ebx
				inc ecx
				dec ecx
			.endw 
			pop ebx
		.endif
		.if [i] != 0
			mov ecx, [szRes]
			.while ecx > 0
				dec ecx
				mov dword ptr[edx+ecx*4], 0h
				inc ecx
				dec ecx
			.endw
			mov [ebx].buf, edx
		.endif
		pop eax
		
		mov edx, [i]
		mov ecx, edx
		imul ecx, 4
		add eax, ecx
		mov ecx, dword ptr [eax]
		mov [num], ecx
		invoke bignum_mul_ui, ebx, edi, [num]
		
		mov ecx, [i]
		.while ecx > 0
			invoke sdvig, ebx
			dec ecx
		.endw
		
		mov edx, [ebx].buf
		.if [i] != 0
			invoke sum_array, ebx, [tmp_buf]
		.endif
		
		dec [sz2]
		inc [i]
	.endw
	mov ecx, [sign]
	mov [ebx].sign, ecx
	
	mov ecx, [ebx].chunk_count
	mov eax, [ebx].buf
	xor edx, edx
	.while ecx > 0
		dec ecx
		.if dword ptr[eax+4*ecx] == 0
			.if ecx != 0
				inc edx
			.endif
		.else
			.break		
		.endif
		inc ecx
		dec ecx
	.endw
	
	mov ecx, [ebx].chunk_count
	sub ecx, edx
	invoke bignum_realloc, ebx, ecx
	
	ret
bignum_mul endp

main proc c argc:DWORD, argv:DWORD, envp:DWORD
    local bn1:bignum
    local bn2:bignum
    local res:bignum
	
	invoke bignum_set_str, addr bn1, $CTA0("FFfFFFFFFFFFFFFFFFFFFFFF")
	invoke bignum_set_str, addr bn2, $CTA0("123")
	;invoke bignum_set_i, addr bn2, 123456h
	invoke bignum_print, addr bn1
	invoke bignum_print, addr bn2
	
	
	;invoke bignum_add_i, addr bn1, 1h, 0
	;invoke bignum_print, addr bn1
	
	;invoke bignum_sub_i, addr bn1, 0ffffffffh, 0
	;invoke bignum_print, addr bn1
	
	;invoke bignum_and, addr res, addr bn1, addr bn2
	;invoke bignum_add, addr res, addr bn1, addr bn2
	;invoke bignum_sub, addr res, addr bn1, addr bn2
	invoke bignum_mul, addr res, addr bn1, addr bn2
	invoke bignum_print, addr res
	
    mov eax, 0
    ret
main endp

end
