function strToBytes(str){
  var bytes = [];

  for (var i = 0; i < str.length; i++)
    bytes.push(str.charCodeAt(i));

  return bytes;
}

function bytesToStr(bytes){
  var str = '';

  for (var i = 0; i < bytes.length; i++)
    str += String.fromCharCode(bytes[i])

  return str;
}

function join(array, separator){
  separator = separator || ', ';

  var str = '';

  for (var i = 0; i < array.length; i++){
    if(str != '')
      str += separator;
    str += array[i];
  }

  return str;
}

function strToBase64(bytes){ return btoa(bytes); }
function bytesToBase64(bytes, url){ var res = strToBase64(bytesToStr(bytes)); if(url) res = res.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); return res; }

function base64ToStr(base64str){ return atob(base64str.replace(/-/g, '+').replace(/_/g, '/')); }
function base64ToBytes(str){ return strToBytes(base64ToStr(str)); }

function base32ToStr(base32str){ return bytesToStr(base32ToBytes(base32str)); }
function base32ToBytes(str){
  str = str.replace(/[\s=]+/g, '');

  var bitCount = 0, bitData = 0, bytes = [];
  for (var i = 0; i < str.length; i++) {
    putBits(5, _base32CharcodeToInt(str.charCodeAt(i)));
  }
  return bytes;

  function putBits(cnt, data) {
    bitData = (bitData << cnt) | data;
    bitCount += cnt;
    while (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((bitData >> bitCount) & 0xff);
    }
  }
}

function strToBase32(bytes){ return bytesToBase32(strToBytes(bytes)); }

function bytesToBase32(bytes) {
  var result = '';
  var bitData = 0, bitCount = 0;
  for (var i = 0; i < bytes.length; i++) {
    putBits(8, bytes[i]);
  }
  if (bitCount > 0) putBits(5, 0);
  while (result.length % 8 > 0) result += '=';
  return result;

  function putBits(cnt, data) {
    bitData = (bitData << cnt) | data;
    bitCount += cnt;
    while (bitCount >= 5) {
      bitCount -= 5;
      result += String.fromCharCode(_base32IntToCharcode((bitData >> bitCount) & 0x1f));
    }
  }
}

function _base32CharcodeToInt(chCode) {
  if (chCode >= 65 && chCode <= 90)="" return="" chcode="" -="" 65;="" a-z=""> 0-25
  if (chCode >= 97 && chCode <= 122)="" return="" chcode="" -="" 97;="" a-z=""> 0-25
  if (chCode >= 50 && chCode <= 50="" 55)="" return="" chcode="" -="" +="" 26;="" 2-7=""> 26-31
  throw new Error('Base32 invalid charcode')
}
function _base32IntToCharcode(i) {
  if (i >= 0 && i <= 25)="" return="" i="" +="" 65;="" if="" (i="">= 26 && i <= 2="=" 26="" 31)="" return="" i="" -="" +="" 50;="" throw="" new="" error('base32="" invalid="" int')="" }="" function="" bytestohex(bytes,="" separator){="" separator="separator" ||="" '';="" bytes.map(function(x){="" padleft(x.tostring(16),'00');="" }).join(separator);="" strtohex(str,="" bytestohex(strtobytes(str),="" separator);="" hextostr(hexstr){="" bytestostr(hextobytes(hexstr));="" hextobytes(str){="" var="" filteredstr="str.toLowerCase().replace(/[^0-9a-f]/g," '');="" if(filteredstr.length="" %="" 1)="" filteredstr;="" bytes="[];" for(var="" <="" filteredstr.length;="" bytes.push(parseint(filteredstr.substr(i,="" 2),="" 16));="" bytes;="" bytestooct(bytes,="" padleft(x.tostring(8),'000');="" octtobytes(str){="" 3),="" 8));="" bytestobinary(bytes){="" join(bytes.map(function(x){="" padleft(x.tostring(2),'00000000');="" }),="" '="" ');="" binarytobytes(str){="" 8),="" 2));="" padleft(str,="" padpattern){="" string(padpattern="" str).slice(-padpattern.length);="" htmlencode(value){="" $('<div="">').text(value).html();
}

function htmlDecode(value){
  return $('<div>').html(value).text();
}

function reverse(str){
  return str.split("").reverse().join("");
}

function rotMod(c, n, base){
  var val = c - base + n;
  if(val < 0) val += 26;
  if(val > 25) val -= 26;
  return base + val;
}

function rot(str, n){
  var result = '';
  for(var i = 0; i < str.length; i++){
    var c = str.charCodeAt(i);
    if(97 <= c="" &&="" <="122)" n,="" 97);="" else="" if(65="" 65);="" result="" +="String.fromCharCode(c);" }="" return="" result;="" var="" morsetable="{" a:="" '.-',="" b:="" '-...',="" c:="" '-.-.',="" d:="" '-..',="" e:="" '.',="" f:="" '..-.',="" g:="" '--.',="" h:="" '....',="" i:="" '..',="" j:="" '.---',="" k:="" '-.-',="" l:="" '.-..',="" m:="" '--',="" n:="" '-.',="" o:="" '---',="" p:="" '.--.',="" q:="" '--.-',="" r:="" '.-.',="" s:="" '...',="" t:="" '-',="" u:="" '..-',="" v:="" '...-',="" w:="" '.--',="" x:="" '-..-',="" y:="" '-.--',="" z:="" '--..',="" 0:="" '-----',="" 1:="" '.----',="" 2:="" '..---',="" 3:="" '...--',="" 4:="" '....-',="" 5:="" '.....',="" 6:="" '-....',="" 7:="" '--...',="" 8:="" '---..',="" 9:="" '----.',="" '.':="" '.-.-.-',="" '?':="" '..--..',="" '\'':="" '.----.',="" '"':="" '.-..-.',="" '="" ':="" '-..-.',="" '@':="" '.--.-.',="" -...-',="" '$':="" '...-..-',="" '!':="" '---.',="" '(':="" '-.--.-',="" ')':="" '[':="" '-.--.',="" ']':="" '+':="" '.-.-.',="" '-':="" '-....-',="" '_':="" '..--.-',="" ':':="" '---...',="" ';':="" '-.-.-.',="" '\n':="" '.-.-'="" };="" morsetablerev="Array();" for(var="" morsekey="" in="" morsetable)="" morsetablerev[morsetable[morsekey]]="morseKey;" function="" morsedecode(str){="" \u2022="bullet" \u2012="figure" dash="" \u2013="en" \u2014="em" \u2015="horizontal" bar="" \u2212="minus" sign="" str="str.replace(/[\u2022\*\+]/g," '.').replace(="" [\u2012\u2013\u2014\u2015\u2212_]="" g,="" '-');="" parts="str.split('" ');="" ;="" i="0;" parts.length;="" i++){="" value="morseTableRev[parts[i]];" ?="" :="" parts[i];="" morseencode(str){="" str.length;="" if(c)="" =="" ''="" ')="" c;="" result.replace(="" \.="" '\u2022'="" *="" bullet="" ).replace(="" -="" '\u2212'="" minus="" );="" bytestointstr(bytes){="" new="" biginteger(bytestohex(bytes),16).tostring(10);="" intstrtobytes(intstr){="" hextobytes(new="" biginteger(intstr,="" 10).tostring(16));="" bytestodeclist(bytes){="" join(bytes,="" declisttobytes(declist){="" [0-9]+="" g.matches(declist).map(function(x){="" parseint(x);="" });="" urldecode="decodeURIComponent;" urlencode="encodeURIComponent;" string.prototype.repeat="function(count)" {="" if="" (count="" 1)="" '';="" ,="" pattern="this.valueOf();" while=""> 1) {
    if (count & 1) result += pattern;
    count >>= 1, pattern += pattern;
  }
  return result + pattern;
};

var hashInfos = {
  md5:       { algo: CryptoJS.algo.MD5,       hashLen: 16, bitLenSize:  8, blockSize:  64, littleEndian: true  },
  ripemd160: { algo: CryptoJS.algo.RIPEMD160, hashLen: 20, bitLenSize:  8, blockSize:  64, littleEndian: true  },
  sha1:      { algo: CryptoJS.algo.SHA1,      hashLen: 20, bitLenSize:  8, blockSize:  64, littleEndian: false },
  sha256:    { algo: CryptoJS.algo.SHA256,    hashLen: 32, bitLenSize:  8, blockSize:  64, littleEndian: false },
  sha512:    { algo: CryptoJS.algo.SHA512,    hashLen: 64, bitLenSize: 16, blockSize: 128, littleEndian: false }
};

function endiannessSwitch(num){
  return (num >>> 24) | ((num >>> 8) & 0xff00) | ((num & 0xff00) << 8) | (num << 24);
}

function lengthExtensionAttack(hashInfo, data, origSign, secretLen, appendText) {
  // create hash
  var hashAlgo = hashInfo.algo.create();

  // restore state
  var origSignWords = CryptoJS.enc.Latin1.parse(origSign).words;

  if(hashInfo.littleEndian)
    for(var i = 0; i < origSignWords.length; i++)
      origSignWords[i] = endiannessSwitch(origSignWords[i]);

  if(hashAlgo._hash.toX32) // 64-bit words
    for(var i = 0; i < origSignWords.length / 2; i++)
      hashAlgo._hash.words[i] = (CryptoJS.x64.Word.create(origSignWords[i * 2], origSignWords[i * 2 + 1]));
  else
    hashAlgo._hash.words = origSignWords;

  // append new text
  hashAlgo.update(appendText);

  // calculate byte lengths for <secret> + <data> + <padding> + <bit len="" of="" data="">
  var byteLenWoPadding = secretLen + data.length + hashInfo.bitLenSize;
  var fullByteSize = ((Math.floor(byteLenWoPadding / hashInfo.blockSize) + 1) * hashInfo.blockSize);
  var paddingLen = fullByteSize - byteLenWoPadding;
  hashAlgo._nDataBytes += fullByteSize;

  // calculate new signature
  var newSignature = CryptoJS.enc.Latin1.stringify(hashAlgo.finalize());

  var bitLen = (data.length + secretLen) * 8;
  var bitLenStr = bytesToStr(new Array(0, 0, 0, 0, bitLen >>> 24, bitLen >>> 16 & 0xff, bitLen >>> 8 & 0xff, bitLen & 0xff));
  if(hashInfo.littleEndian)
    bitLenStr = reverse(bitLenStr);

  var newData = data + '\x80' + '\x00'.repeat(paddingLen - 1 + (hashInfo.bitLenSize - 8)) + bitLenStr + appendText;

  return { newData: newData, newSignature: newSignature };
}

var lastStr = '', lastBytes = Array(), lastExcept;

try {
  var navigationParts = location.hash.substr(1).split('/');
  var pageName = navigationParts[0];
  if(pageName == 'conv')
    lastStr = urldecode(navigationParts[1] || "");
  else if(pageName == 'hash')
    $('#tabHash').tab('show');
  else if(pageName == 'rsa')
    $('#tabRSA').tab('show');
  else if(pageName == 'upc')
    $('#tabUPC').tab('show');
} catch(err){ }

function readBlob(blob){
    return new Promise(function(resolve, reject){
        var reader = new FileReader();
        reader.onload = function() {
            resolve(reader.result);
        };
        reader.onerror = function(e) {
            reject(e);
        };
        reader.readAsBinaryString(blob);
    });
}

function keyEventSignup(item, func){
    item.keypress(func);
    item.keyup(func);
}

$(function(){
  for(var i = 1; i <= 25;="" i++)="" $('#rotarea').append('<p="">\
                <input type="text" id="rot'+i+'" placeholder="ROT-'+i+'" class="form-control input-sm">\
                <span class="label label-'+(i==13 ? 'danger' : 'primary')+' inputLabel">ROT'+i+'</span>\
            <p></p>');

  var inpAscii = $('#inpAscii'), inpHex = $('#inpHex'), inpOct = $('#inpOct'), inpDec = $('#inpDec'), inpBase64 = $('#inpBase64'), inpBase64Url = $('#inpBase64Url'), inpBase32 = $('#inpBase32'),
    inpUrlEnc = $('#inpUrlEnc'), inpHtmlEnc = $('#inpHtmlEnc'), inpBinary = $('#inpBinary'), inpReverse = $('#inpReverse'), inpMorse = $('#inpMorse'), inpInteger = $('#inpInteger'),
    md5 = $('#md5'), ripemd160 = $('#ripemd160'), sha1 = $('#sha1'), sha256 = $('#sha256'), sha512 = $('#sha512'), sha3 = $('#sha3'), dataLength = $('#dataLength'), dataLengthBits = $('#dataLengthBits'),
    lLowercase = $('#lLowercase'), lUppercase = $('#lUppercase'),
    showRot = $('#showRot'), showHash = $('#showHash'), showGeneral = $('#showGeneral'), showMisc = $('#showMisc'),
    inpHashOrigData = $('#hashOrigData'), inpHashOrigSign = $('#hashOrigSign'), inpHashSecretLen = $('#hashSecretLen'),
    inpHashAppendData = $('#hashAppendData'), inpHashNewData = $('#hashNewData'), inpHashNewSignature = $('#hashNewSignature'),
    txtHashAlgorithm = $('#txtHashAlgorithm');

  var showButtons = Array(showRot, showHash, showGeneral, showMisc);

  var inpRots = Array();
  for(var i = 1; i <= 25;="" i++)="" inprots[i]="$('#rot'" +="" i);="" $('#btndownload').click(function(){="" var="" a="document.createElement("a");" document.body.appendchild(a);="" a.style="display:none" ;="" blob="new" blob([new="" uint8array(lastbytes)],="" {type:="" "octet="" stream"});="" url="window.URL.createObjectURL(blob);" a.href="url;" a.download="data.txt" a.click();="" window.url.revokeobjecturl(url);="" });="" fileinput="$('#fileInput');" $('#btnupload').click(function(){="" fileinput.click();="" fileinput.on('change',="" function(){="" readblob(fileinput.get(0).files[0]).then(function(filecontent){="" convrefreshall(filecontent);="" $('#btnreverse').click(function(){="" convrefreshall(reverse(laststr));="" $('#maintabs="" a').on('shown.bs.tab',="" function="" (e)="" {="" if(e.target.id="=" 'tabascii')="" convrefreshtolast();="" else="" 'tabhash')="" refreshhash();="" 'tabrsa')="" window.location.hash="rsa" 'tabupc')="" dragleaveclear;="" body="$("body");" filedropshadow="$("#fileDropShadow");" body.on("dragover",="" function(event)="" event.preventdefault();="" event.stoppropagation();="" if(dragleaveclear){="" cleartimeout(dragleaveclear);="" dragleaveclear="null;" }="" filedropshadow.show();="" body.on("dragleave",="" if(dragleaveclear)="" filedropshadow.hide();="" },="" 100);="" body.on("drop",="" readblob(event.originalevent.datatransfer.files[0]).then(function(filecontent){="" morsestyle(){="" inpmorse.toggleclass('morsecontent',="" inpmorse.val()="" !="" );="" keyeventsignup(inpmorse,="" morsestyle);="" $("#showbuttons="" label").click(function(e){="" settimeout(function(){="" localstorage.setitem($(e.target).attr('id')="" '.active',="" $(e.target).hasclass('active'));="" 0);="" for(var="" i="0;" <="" showbuttons.length;="" i++){="" isactive="localStorage.getItem(showButtons[i].attr('id')" '.active');="" if(isactive="==" null)="" continue;="" =="=" "true";="" showbuttons[i].toggleclass('active',="" isactive);="" $(showbuttons[i].attr('data-target')).toggleclass('in',="" isactive).toggleclass('collapse',="" !isactive);="" historydisabled="false;" convrefreshall(bytesorstr,="" except,="" force){="" start="new" date().gettime();="" isstr="$.type(bytesOrStr)" "string";="" str="isStr" ?="" bytesorstr="" :="" bytestostr(bytesorstr);="" bytes="!isStr" strtobytes(bytesorstr);="" if(str="=" laststr="" &&="" !force)="" return;="" lastbytes="bytes;" lastexcept="except;" datalength.text(str.length);="" datalengthbits.text(str.length="" *="" 8);="" if(except="" inpascii.val(str);="" if(!historydisabled="" history.replacestate="" $("#tabascii").parent().hasclass('active'))="" try="" history.replacestate(null,="" null,="" '#conv="" '="" urlencode(str));="" catch(e)="" console.log('history.replacestate="" failed:="" e);="" if(showgeneral.hasclass('active')){="" inpdec.val(bytestodeclist(bytes));="" inphex.val(bytestohex(bytes,="" '));="" inpoct.val(bytestooct(bytes,="" inpbase64.val(bytestobase64(bytes,="" false));="" inpbase64url.val(bytestobase64(bytes,="" true));="" inpbase32.val(bytestobase32(bytes));="" inpurlenc.val(urlencode(str));="" inphtmlenc.val(htmlencode(str));="" inpbinary.val(bytestobinary(bytes));="" inpinteger.val(bytestointstr(bytes));="" if(showmisc.hasclass('active'))="" if="" (except="" inpreverse.val(reverse(str));="" inpmorse.val(morseencode(str));="" llowercase.val(str.tolowercase());="" luppercase.val(str.touppercase());="" morsestyle();="" if(showrot.hasclass('active'))="" inprots[i].val(rot(str,i));="" if(showhash.hasclass('active')){="" wordarray="CryptoJS.enc.Latin1.parse(str);" md5.val(cryptojs.md5(wordarray));="" ripemd160.val(cryptojs.ripemd160(wordarray));="" sha1.val(cryptojs.sha1(wordarray));="" sha256.val(cryptojs.sha256(wordarray));="" sha512.val(cryptojs.sha512(wordarray));="" sha3.val(cryptojs.sha3(wordarray));="" console.log('refreshall:="" (new="" date().gettime()="" -="" start)="" 'ms=""> ' + str);
  }

  function convRefreshToLast(){ convRefreshAll(lastStr, lastExcept, true); }

  convRefreshToLast();

  RegExp.prototype.matches = function(str){
    var matches = [];
    var match;
    while(match = this.exec(str))
      matches.push(match[0]);
    return matches;
  };

  function inputByteHandle(input, toByteConv, funcToCall){
    keyEventSignup(input, function(){
      var inputVal = input.val();
      try {
        var bytes = toByteConv(inputVal);
        input.parent().removeClass('has-error');
      } catch(err) {
        input.parent().addClass('has-error');
      }
      funcToCall(bytes, input);
    });
  }

  function convInputByteHandle(input, toByteConv){
    inputByteHandle(input, toByteConv, convRefreshAll);
  }

  convInputByteHandle(inpAscii, strToBytes);
  convInputByteHandle(inpDec, decListToBytes);
  convInputByteHandle(inpHex, hexToBytes);
  convInputByteHandle(inpOct, octToBytes);
  convInputByteHandle(inpBase64, base64ToBytes);
  convInputByteHandle(inpBase64Url, base64ToBytes);
  convInputByteHandle(inpBase32, base32ToBytes);
  convInputByteHandle(inpUrlEnc, urldecode);
  convInputByteHandle(inpHtmlEnc, htmlDecode);
  convInputByteHandle(inpBinary, binaryToBytes);
  convInputByteHandle(inpReverse, reverse);
  convInputByteHandle(inpMorse, morseDecode);
  convInputByteHandle(inpInteger, intStrToBytes);
  for(var i = 1; i <= 25;="" i++)="" convinputbytehandle(inprots[i],="" function(i){="" return="" function(str){="" rot(str,="" -i);="" };="" }(i));="" function="" detectformat(text){="" var="" onlydigits="!!/^[0-9]+$/.exec(text);" onlyhex="!!/^[0-9a-fA-F" ]+$="" .exec(text);="" onlyb64="!!/^[0-9a-zA-Z+=/]+$/.exec(text);" hasloweralpha="!!/[a-z]/.exec(text);" hasupperalpha="!!/[A-Z]/.exec(text);" hasb64specchar="!!/[/+=]/.exec(text);" containsspace="!!/" format="ascii" ;="" if(onlydigits="" &&="" containsspace)="" else="" if(onlyhex)="" if(onlyb64="" !containsspace="" hasb64specchar){="" try="" {="" atob(text);="" }="" catch(e)="" console.log('detectformat',="" format,="" text:="" text,="" onlydigits:="" onlydigits,="" onlyhex:="" onlyhex,="" onlyb64:="" onlyb64,="" containsspace:="" });="" format;="" formatinputget(input){="" component="input.closest('.formatSelector');" formattedvalue="input.val();" isautoformat="format" =="auto" if(isautoformat)="" inputlabel="component.find('.inputLabel');" inputlabel.css('display',="" ?="" 'block'="" :="" 'none');="" inputlabel.text(format.touppercase());="" inputlabel.toggleclass('label-primary',="" 'ascii');="" inputlabel.toggleclass('label-danger',="" 'hex');="" inputlabel.toggleclass('label-success',="" 'b64');="" inputlabel.toggleclass('label-info',="" 'dec');="" plainvalue;="" if(format="=" 'hex')="" plainvalue="bytesToStr(hexToBytes(formattedValue));" 'b64')="" 'b32')="" 'dec')="" 'int')="" formatinputset(input,="" newvalue){="" formattedvalue;="" input.val(formattedvalue);="" refreshhash(){="" origdata="formatInputGet(inpHashOrigData);" origsign="formatInputGet(inpHashOrigSign);" secretlen="parseInt(inpHashSecretLen.val());" appenddata="formatInputGet(inpHashAppendData);" hashinfoname="origSign.length" 'md5'="" origsign.length="=" hashinfos.sha1.hashlen="" 'sha1'="" hashinfos.sha256.hashlen="" 'sha256'="" hashinfos.sha512.hashlen="" 'sha512'="" null;="" txthashalgorithm.text(hashinfoname="" hashinfoname.touppercase()="" "could="" not="" detect="" hash="" type!");="" result="hashInfoName" lengthextensionattack(hashinfos[hashinfoname],="" origdata,="" origsign,="" secretlen,="" appenddata)="" newsignature:="" "",="" newdata:="" ""="" formatinputset(inphashnewsignature,="" result.newsignature);="" formatinputset(inphashnewdata,="" result.newdata);="" if(history.replacestate="" $("#tabhash").parent().hasclass('active'))="" history.replacestate(null,="" null,="" '#hash="" '="" +="" urlencode(origdata)="" "="" strtohex(origsign)="" urlencode(secretlen="" ||="" 0)="" urlencode(appenddata));="" new="" array(inphashorigdata,="" inphashorigsign,="" inphashsecretlen,="" inphashappenddata).foreach(function(x){="" keyeventsignup(x,="" refreshhash);="" $('.formatselector="" a').click(function(e){="" a="$(e.target);" a.closest('.formatselector').find('.selval').text(a.text());="" refreshhash();="" if(pagename="=" 'hash'){="" if(navigationparts.length=""> 1) inpHashOrigData.val(urldecode(navigationParts[1]));
    if(navigationParts.length > 2) inpHashOrigSign.val(navigationParts[2]);
    if(navigationParts.length > 3) inpHashSecretLen.val(urldecode(navigationParts[3]));
    if(navigationParts.length > 4) inpHashAppendData.val(urldecode(navigationParts[4]));
  }

  refreshHash();
//        console.log('lengthExtensionAttack MD5', lengthExtensionAttack(hashInfos.md5, 'hello', '11e2d168019acd14ecdb5ec80a98bb38', 6, 'bello'));
//        console.log('lengthExtensionAttack SHA1', lengthExtensionAttack(hashInfos.sha1, 'hello', 'a590ccecb687967079362e49b7fe6c5258d09be5', 6, 'bello'));
//        console.log('lengthExtensionAttack SHA256', lengthExtensionAttack(hashInfos.sha256, 'hello', '1d4d234df92246e120bc62a10d8751882494a8a9bae09c494a519a783a128732', 6, 'bello'));
//        console.log('lengthExtensionAttack SHA512', lengthExtensionAttack(hashInfos.sha512, 'hello', 'adee6c2ae315a8dedd04462b8ed40221f699f521d5c74feac968e6efb96513d9f6f9aa6ce4b52fec3bd3816340610fab8f182b57fd9bbd53a431dfc87fd6a5e7', 6, 'bello'));
//        console.log('lengthExtensionAttack RIPEMD160', lengthExtensionAttack(hashInfos.ripemd160, 'hello', 'eeaf34a1c3687ea7082a38a6eb45c6ea19080251', 6, 'bello'));
});
</=></=></=></bit></padding></data></secret></=></div></=></=></=></=></=>