/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
/*

 Counter block mode compatible with  Dr Brian Gladman fileenc.c
 derived from CryptoJS.mode.CTR 
 Jan Hruby jhruby.web@gmail.com
*/
CryptoJS.mode.CTRGladman=function(){function h(a){if(255===(a>>24&255)){var c=a>>16&255,b=a>>8&255,e=a&255;255===c?(c=0,255===b?(b=0,255===e?e=0:++e):++b):++c;a=0+(c<