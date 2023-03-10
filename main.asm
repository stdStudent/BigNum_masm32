.686
.model flat, stdcall
option casemap:none

include c:\masm32\include\msvcrt.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\user32.inc
include c:\masm32\include\Strings.mac

;function1 proto :DWORD, :DWORD

bignum struct
    chunk_count dword    ?  ; ????? ?????? (? dowrd'???) ? ??????? buf   
    sign        dword    ?  ; ???? ????? (sign = 0 - ?????., sign = 1 - ?????.)   
    buf         dword    ?  ; ????????? ?? ?????? ? ??????? ??????
bignum ends

; ??????? ????? - ?????? dword 
; buf[0] - dword, buf[1] - dword, ..., buf[i] - dword
; 13782|AFC53268|493FFFD4
; buf[0] = 493FFFD4
; buf[1] = AFC53268
; buf[2] = 13782

;??
; 1. + ? -
; 2. 
.data


.data?
 
 
.const
new_line db 13,10,0
format_hex db "%08X", 0
format_hex_first db "%X", 0
minus db "-", 0


.code
; ???????? ?????? ??? ?????? dword'?? buf ??????? chunk_count 
; ? ????????? ????????? ???????? ?????
bignum_init_null proc c uses edi ecx, bn: ptr bignum, chunk_count: dword
    mov edi, [bn]               ; ???????? ? edi ????????? ?? ????????? ???????? ?????
    assume edi:ptr bignum
    mov ecx, [chunk_count]
    mov [edi].chunk_count, ecx  ; ?????????????? ???? chunk_count
    mov [edi].sign, 0           ; ?????????????? ???? sign
    imul ecx, 4
    invoke crt_malloc, ecx      ; ???????? ?????? ??? ?????? ??????? 4*chunk_count
    mov [edi].buf, eax          ; ?????????????? ???? buf
    
    ; ???????? ?????
    mov ecx, [edi].chunk_count
    .while ecx > 0
		mov dword ptr [eax], 0
		dec ecx
		add eax, 4 ; next chunk
    .endw
    
    ret
bignum_init_null endp


;?????????????? ??????????? ??????? ?????
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
	; return (char*)str + len - n ?????? ???????? n ????????
	invoke crt_strlen, s ; eax - ???-?? ????????
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
    ; ????????? ????
    mov cl, byte ptr [esi]
    .if cl == "-"
		mov [sign], 1
		add esi, 1
    .endif
    
    ;????????? ???-?? ????????, ????????? ?? 8 ? ????????? ? ??????? ???????
	;? ????? ? ??????? ????? a_to_h 
    
    invoke crt_strlen, esi ; eax - ???-?? ????????
    mov ecx, eax    ; ????????? ????? ??????
    mov ebx, 8      ; ????????
    xor edx, edx
    div ebx         ; eax/ebx -> eax
    .if edx != 0    ; ???? ???? ???????
		add eax, 1  ; ????????? ? ??????? ???????
    .endif
    mov ebx, eax    ; ????????? ???-?? ??????
    
    invoke bignum_init_null, [bn], eax
    .if [sign] != 0
		mov [edi].sign, 1
    .endif
    
    
    xor eax, eax
    mov edi, [edi].buf
    .while [i] < ebx
		invoke lastN, esi, 8 ; ????????? 8 ???????? ? eax
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
		invoke crt_memcpy, eax, esi, ecx ; ???????? ????????? 8 ????????
		pop ecx
		mov esi, eax
		mov byte ptr [esi+ecx], 0 ; ???????? \0 str[strlen] = '\0'
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


; Todo: do not print 0's
; 000000000|000000002
; -> 000000002
bignum_print proc c bn: ptr bignum
     ; for(int i = bn.chunk_count-1; i >= 0; --i)
    ;     printf(format_hex, bn.buf[i]);

    local i: dword

    mov edi, [bn]
    assume edi: ptr bignum
    mov ecx, [edi].chunk_count
    mov [i], ecx                  ; i = bn.chunk_count
    ;dec [i]                       ; --i

	; ??????? ??????? "-", ???? ????? ?????????????
	mov esi, [edi].sign
	.if esi == 1
		invoke crt_printf, addr minus
	.endif

	; ?????? ???? ??? ?????????? ?????
	mov esi, [edi].buf
    mov edx, [i] ; ????????? i
	dec edx
    imul edx, 4  ; ???????? ? ???????
    add esi, edx ; ???????? ?? ?????
    invoke crt_printf, addr format_hex_first, dword ptr [esi]
    dec [i]


	; ??????? ???? ?????
    .while [i] > 0  ; ???????? ???, ??? ??????
        mov esi, [edi].buf
        mov edx, [i] ; ????????? i
		dec edx
        imul edx, 4  ; ???????? ? ???????
        add esi, edx ; ???????? ?? ?????
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
    .while [min_size] > 0 ; ???????????, ?????? >= 0, ????? ?????? > 0
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
    mov [old_sz], ecx           ; ????????? ?????? ??????
    
    mov ecx, [new_chunk_size]
    mov [edi].chunk_count, ecx  ; ????????? ????? ??????
    imul ecx, 4
    
    mov esi, [edi].buf 
    invoke crt_realloc, esi, ecx
    mov [edi].buf, eax          ; ???????????? ????? ?????
    
    mov esi, eax
    mov ecx, [old_sz]
    imul ecx, 4
    add esi, ecx       ; ????????? ?? ????? ??????? ??????
    
    ; ?????? ?????
    mov ecx, [old_sz]
    .while ecx < [edi].chunk_count
		mov dword ptr [esi], 0
		inc ecx
		add esi, 4 ; next chunk
    .endw
    
	ret ; eax
bignum_realloc endp

exit_err proc c, msg:dword
	invoke crt_printf, $CTA0("%s\n"), msg
	invoke crt_exit, 1
exit_err endp

;   13782|AFC53268|493FFFD4
; +                12345678
;   13782|AFC53268|5B74564C

bignum_add_i proc c uses edi esi ecx, bn: ptr bignum, num: dword, pos: dword
	local sz: dword
	
	; ??? ????????????
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
    
    ; ????????? ????????????
    .while CARRY?
		mov ecx, [sz]
		inc [pos]
		.if [pos] == ecx
			inc ecx
			invoke bignum_realloc, edi, ecx
			mov esi, eax
			mov ecx, [sz]   ; ????????? ?? buf[0], ????? ??????? ?? buf[last]
			imul ecx, 4
			add esi, ecx
			sub esi, 4      ; ????? ?? ??????? ?? ??????? ???????
		.endif
		
		add esi, 4
		add dword ptr [esi], 1
    .endw
    
	ret
bignum_add_i endp

; proc sub_i
bignum_sub_i proc c uses edi esi ecx ebx, bn: ptr bignum, num: dword, pos: dword
	local sz: dword
	
	; ??? ????????????
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
		;invoke exit_err, $CTA0("bignum_sub_i(): arg1 must be lower than arg2")
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

; Todo invoke memcpy
bignum_sub proc c res: ptr bignum, arg1: ptr bignum, arg2: ptr bignum
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
    
    mov edi, [res]
    assume edi: ptr bignum
    
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
    
    invoke crt_memcpy, edi, esi, SIZEOF bignum
    
    mov ecx, [ebx].buf
    mov eax, [ebx].chunk_count
    mov [sz], eax
    .if [regular_bool] == 0
		.while [sz] > 0
			mov eax, dword ptr [ecx]
			invoke bignum_sub_i, edi, eax, [count]
			
			add ecx, 4
			
			inc [count]
			dec [sz]
		.endw
	;.elseif [minus_bool_1] != 0
	;	.while [sz] > 0
	;		mov eax, dword ptr [ecx]
	;		invoke bignum_add_i, edi, eax, [count]
	;		
	;		add ecx, 4
	;		
	;		inc [count]
	;		dec [sz]
	;	.endw
	;.elseif [minus_bool_2] != 0
	;	.while [sz] > 0
	;		mov eax, dword ptr [ecx]
	;		invoke bignum_add_i, edi, eax, [count]
	;		
	;		add ecx, 4
	;		
	;		inc [count]
	;		dec [sz]
	;	.endw
	.else
		.while [sz] > 0
			mov eax, dword ptr [ecx]
			invoke bignum_add_i, edi, eax, [count]
			
			add ecx, 4
			
			inc [count]
			dec [sz]
		.endw
	.endif
    
    ret
bignum_sub endp

; Todo invoke memcpy
bignum_add proc c uses edi esi ebx ecx eax, res: ptr bignum, arg1: ptr bignum, arg2: ptr bignum
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
    
    mov edi, [res]
    assume edi: ptr bignum
    
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
    
    invoke crt_memcpy, edi, esi, SIZEOF bignum
    
    mov ecx, [ebx].buf
    mov eax, [ebx].chunk_count
    mov [sz], eax
    .if [regular_bool] == 0
		.while [sz] > 0
			mov eax, dword ptr [ecx]
			invoke bignum_add_i, edi, eax, [count]
			
			add ecx, 4
			
			inc [count]
			dec [sz]
		.endw
	;.elseif [minus_bool_1] != 0
	;	;invoke bignum_sub, edi, esi, ebx
	;	.while [sz] > 0
	;		mov eax, dword ptr [ecx]
	;		invoke bignum_sub_i, edi, eax, [count]
	;		
	;		add ecx, 4
	;		
	;		inc [count]
	;		dec [sz]
	;	.endw
	;.elseif [minus_bool_2] != 0
	;	;invoke bignum_sub, edi, ebx, esi
	;	.while [sz] > 0
	;		mov eax, dword ptr [ecx]
	;		invoke bignum_sub_i, edi, eax, [count]
	;		
	;		add ecx, 4
	;		
	;		inc [count]
	;		dec [sz]
	;	.endw
	.else
		.while [sz] > 0
			mov eax, dword ptr [ecx]
			invoke bignum_sub_i, edi, eax, [count]
			
			add ecx, 4
			
			inc [count]
			dec [sz]
		.endw
	.endif
    
    ret
bignum_add endp

;         0FF00E1|000200E2               000200E2         0FF00E1
;	  	          11111111               11111111         11111111
;   ----------------------               ------------    --------------
; 11000E|FFEF2222|33331102              2231|33331102     11000E|FFEEFFF1


bignum_mul_ui proc c uses edi esi ebx ecx, res: ptr bignum, arg1: ptr bignum, arg2: dword
    local sz:dword
    local count:dword
    
    mov edi, [res]
    assume edi: ptr bignum
    
    mov esi, [arg1]
    assume esi: ptr bignum
    
    mov ecx, [esi].chunk_count
    inc ecx
    invoke bignum_init_null, edi, ecx
    
    ;mov ecx, [esi].chunk_count
    ;imul ecx, 4
    ;invoke crt_memcpy, [edi].buf, [esi].buf, ecx
    
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

;                   FF0137CD|AA553711
;                   CDEE0000|155EECC0
; -----------------------------------
; cd210cd1|a7e4402c|8ba6fc14|ebeaf8c0
; max: ????? ????????

;          FF0137CD|AA553711
;                   155EECC0
; 1549A7DA|BCD8FC14|EBEAF8C0 

;          FF0137CD|AA553711
;                   CDEE0000
; CD210CD1|929A9851|CECE0000|00000000 ; ?.?. ?????? ????

;   CD210CD1|929A9851|CECE0000|00000000
;            1549A7DA|BCD8FC14|EBEAF8C0 
; +
;   cd210cd1|a7e4402c|8ba6fc14|ebeaf8c0

main proc c argc:DWORD, argv:DWORD, envp:DWORD
    local bn1:bignum
    local bn2:bignum
    local res:bignum
	
	invoke bignum_set_str, addr bn1, $CTA0("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0137CDAA553711")
	invoke bignum_set_str, addr bn2, $CTA0("0")
	;invoke bignum_set_i, addr bn2, 123456h
	invoke bignum_print, addr bn1
	invoke bignum_print, addr bn2
	
	;invoke bignum_add_i, addr bn1, 1h, 0
	;invoke bignum_print, addr bn1
	
	;invoke bignum_add, addr res, addr bn1, addr bn2
	;invoke bignum_print, addr res
	
	;invoke bignum_sub_i, addr bn1, 0ffffffffh, 0
	;invoke bignum_print, addr bn1
	
	;invoke bignum_sub, addr res, addr bn1, addr bn2
	invoke bignum_mul_ui, addr res, addr bn1, -0h
	invoke bignum_print, addr res
	;invoke bignum_print, addr bn1
	;invoke bignum_print, addr bn2
	
    mov eax, 0
    ret
main endp

end
