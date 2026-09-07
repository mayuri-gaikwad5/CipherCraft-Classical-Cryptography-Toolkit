/* ======================================================================
   CIPHER ENGINE
   Every cipher exposes: encrypt(text,key), decrypt(text,key)
   plus helpers used by the process visualizer.
====================================================================== */
const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

function isAlpha(ch){ return /[a-zA-Z]/.test(ch); }
function isUpper(ch){ return ch === ch.toUpperCase() && /[A-Z]/.test(ch); }

/* ---------- Caesar ---------- */
function caesarEncrypt(text, key){
  const k = ((parseInt(key,10) % 26) + 26) % 26;
  return text.split('').map(ch=>{
    if(!isAlpha(ch)) return ch;
    const base = isUpper(ch) ? 65 : 97;
    return String.fromCharCode((ch.charCodeAt(0)-base+k)%26+base);
  }).join('');
}
function caesarDecrypt(text, key){
  return caesarEncrypt(text, -parseInt(key,10));
}

/* ---------- Monoalphabetic ---------- */
function generateMonoKey(){
  const letters = A.split('');
  for(let i=letters.length-1;i>0;i--){
    const j = Math.floor(Math.random()*(i+1));
    [letters[i],letters[j]] = [letters[j],letters[i]];
  }
  return letters.join('');
}
function monoEncrypt(text, key){
  key = key.toUpperCase();
  return text.split('').map(ch=>{
    if(!isAlpha(ch)) return ch;
    const idx = A.indexOf(ch.toUpperCase());
    const out = key[idx];
    return isUpper(ch) ? out : out.toLowerCase();
  }).join('');
}
function monoDecrypt(text, key){
  key = key.toUpperCase();
  return text.split('').map(ch=>{
    if(!isAlpha(ch)) return ch;
    const idx = key.indexOf(ch.toUpperCase());
    const out = A[idx];
    return isUpper(ch) ? out : out.toLowerCase();
  }).join('');
}

/* ---------- Playfair ---------- */
function playfairMatrix(key){
  key = key.toUpperCase().replace(/J/g,'I');
  const seen = [];
  for(const ch of key) if(/[A-Z]/.test(ch) && !seen.includes(ch)) seen.push(ch);
  for(const ch of A){ if(ch==='J') continue; if(!seen.includes(ch)) seen.push(ch); }
  const matrix = [];
  for(let r=0;r<5;r++) matrix.push(seen.slice(r*5,r*5+5));
  return matrix;
}
function findPos(matrix, ch){
  for(let r=0;r<5;r++){ const c = matrix[r].indexOf(ch); if(c!==-1) return [r,c]; }
  return null;
}
function playfairPairs(text){
  text = text.toUpperCase().replace(/[^A-Z]/g,'').replace(/J/g,'I');
  const pairs = [];
  let i=0;
  while(i<text.length){
    const a = text[i];
    let b;
    if(i+1===text.length){ b='X'; i+=1; }
    else{
      b = text[i+1];
      if(a===b){ b='X'; i+=1; }
      else{ i+=2; }
    }
    pairs.push([a,b]);
  }
  return pairs;
}
function playfairEncrypt(text, key){
  const matrix = playfairMatrix(key);
  const pairs = playfairPairs(text);
  let out='';
  for(const [a,b] of pairs){
    const [r1,c1]=findPos(matrix,a), [r2,c2]=findPos(matrix,b);
    if(r1===r2) out += matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5];
    else if(c1===c2) out += matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2];
    else out += matrix[r1][c2] + matrix[r2][c1];
  }
  return out;
}
function playfairDecrypt(text, key){
  const matrix = playfairMatrix(key);
  text = text.toUpperCase().replace(/[^A-Z]/g,'');
  let out='';
  for(let i=0;i<text.length-1;i+=2){
    const a=text[i], b=text[i+1];
    const [r1,c1]=findPos(matrix,a), [r2,c2]=findPos(matrix,b);
    if(r1===r2) out += matrix[r1][(c1+4)%5] + matrix[r2][(c2+4)%5];
    else if(c1===c2) out += matrix[(r1+4)%5][c1] + matrix[(r2+4)%5][c2];
    else out += matrix[r1][c2] + matrix[r2][c1];
  }
  return out;
}

/* ---------- Hill (2x2) ---------- */
function modInverse(a,m){
  a=((a%m)+m)%m;
  for(let x=1;x<m;x++) if((a*x)%m===1) return x;
  return null;
}
function hillMatrix(key){
  key = key.toUpperCase().replace(/[^A-Z]/g,'');
  if(key.length<4) throw new Error('Hill cipher key must have at least 4 letters (2x2 matrix).');
  const n = key.slice(0,4).split('').map(c=>c.charCodeAt(0)-65);
  return [[n[0],n[1]],[n[2],n[3]]];
}
function hillEncrypt(text, key){
  const m = hillMatrix(key);
  text = text.toUpperCase().replace(/[^A-Z]/g,'');
  if(text.length%2!==0) text+='X';
  let out='';
  for(let i=0;i<text.length;i+=2){
    const p1=text.charCodeAt(i)-65, p2=text.charCodeAt(i+1)-65;
    const c1=(m[0][0]*p1+m[0][1]*p2)%26, c2=(m[1][0]*p1+m[1][1]*p2)%26;
    out += String.fromCharCode(c1+65)+String.fromCharCode(c2+65);
  }
  return out;
}
function hillDecrypt(text, key){
  const m = hillMatrix(key);
  const det = (((m[0][0]*m[1][1]-m[0][1]*m[1][0])%26)+26)%26;
  const detInv = modInverse(det,26);
  if(detInv===null) throw new Error('Key matrix is not invertible mod 26 — choose a different key.');
  const inv = [
    [ (m[1][1]*detInv)%26, ((-m[0][1]*detInv)%26+26)%26 ],
    [ ((-m[1][0]*detInv)%26+26)%26, (m[0][0]*detInv)%26 ]
  ];
  text = text.toUpperCase().replace(/[^A-Z]/g,'');
  let out='';
  for(let i=0;i<text.length;i+=2){
    const c1=text.charCodeAt(i)-65, c2=text.charCodeAt(i+1)-65;
    const p1=(inv[0][0]*c1+inv[0][1]*c2)%26, p2=(inv[1][0]*c1+inv[1][1]*c2)%26;
    out += String.fromCharCode(p1+65)+String.fromCharCode(p2+65);
  }
  return out;
}

/* ---------- Vigenere ---------- */
function vigenereEncrypt(text, key){
  key = key.toUpperCase().replace(/[^A-Z]/g,'');
  let k=0, out='';
  for(const ch of text){
    if(isAlpha(ch)){
      const shift = key.charCodeAt(k%key.length)-65;
      const base = isUpper(ch)?65:97;
      out += String.fromCharCode((ch.charCodeAt(0)-base+shift)%26+base);
      k++;
    } else out += ch;
  }
  return out;
}
function vigenereDecrypt(text, key){
  key = key.toUpperCase().replace(/[^A-Z]/g,'');
  let k=0, out='';
  for(const ch of text){
    if(isAlpha(ch)){
      const shift = key.charCodeAt(k%key.length)-65;
      const base = isUpper(ch)?65:97;
      out += String.fromCharCode(((ch.charCodeAt(0)-base-shift)%26+26)%26+base);
      k++;
    } else out += ch;
  }
  return out;
}

/* ---------- One-Time Pad ---------- */
function generateOtpKey(len){
  let out='';
  for(let i=0;i<len;i++) out += A[Math.floor(Math.random()*26)];
  return out;
}
function otpEncrypt(text, key){
  key = key.toUpperCase();
  let k=0, out='';
  for(const ch of text){
    if(isAlpha(ch)){
      if(k>=key.length) throw new Error('Key is too short for this plaintext.');
      const base = isUpper(ch)?65:97;
      const shift = key.charCodeAt(k)-65;
      out += String.fromCharCode((ch.charCodeAt(0)-base+shift)%26+base);
      k++;
    } else out += ch;
  }
  return out;
}
function otpDecrypt(text, key){
  key = key.toUpperCase();
  let k=0, out='';
  for(const ch of text){
    if(isAlpha(ch)){
      if(k>=key.length) throw new Error('Key is too short for this ciphertext.');
      const base = isUpper(ch)?65:97;
      const shift = key.charCodeAt(k)-65;
      out += String.fromCharCode(((ch.charCodeAt(0)-base-shift)%26+26)%26+base);
      k++;
    } else out += ch;
  }
  return out;
}

/* ---------- Rail Fence ---------- */
function railfencePattern(len, rails){
  const pattern=[]; let rail=0, dir=1;
  for(let i=0;i<len;i++){
    pattern.push(rail);
    if(rail===0) dir=1; else if(rail===rails-1) dir=-1;
    rail+=dir;
  }
  return pattern;
}
function railfenceEncrypt(text, key){
  const rails = parseInt(key,10);
  if(rails<2) throw new Error('Rail Fence needs at least 2 rails.');
  const pattern = railfencePattern(text.length, rails);
  const fence = Array.from({length:rails},()=>[]);
  text.split('').forEach((ch,i)=>fence[pattern[i]].push(ch));
  return fence.map(row=>row.join('')).join('');
}
function railfenceDecrypt(text, key){
  const rails = parseInt(key,10);
  const pattern = railfencePattern(text.length, rails);
  const counts = Array(rails).fill(0);
  pattern.forEach(r=>counts[r]++);
  const rowsText=[]; let idx=0;
  for(let r=0;r<rails;r++){ rowsText.push(text.slice(idx, idx+counts[r]).split('')); idx+=counts[r]; }
  const rowPos = Array(rails).fill(0);
  let out='';
  for(const r of pattern){ out += rowsText[r][rowPos[r]]; rowPos[r]++; }
  return out;
}

/* ---------- Columnar Transposition ---------- */
function columnOrder(key){
  return key.split('').map((ch,i)=>[ch,i])
    .sort((a,b)=> a[0]<b[0] ? -1 : a[0]>b[0] ? 1 : a[1]-b[1])
    .map(pair=>pair[1]);
}
function columnarEncrypt(text, key){
  text = text.replace(/ /g,'');
  const nCols = key.length;
  const nRows = Math.ceil(text.length/nCols);
  const padded = text.padEnd(nRows*nCols,'X');
  const grid=[];
  for(let r=0;r<nRows;r++) grid.push(padded.slice(r*nCols,r*nCols+nCols));
  const order = columnOrder(key);
  let out='';
  for(const col of order) for(const row of grid) out += row[col];
  return out;
}
function columnarDecrypt(text, key){
  const nCols = key.length;
  const nRows = Math.ceil(text.length/nCols);
  const order = columnOrder(key);
  const cols = {};
  let idx=0;
  for(const col of order){ cols[col]=text.slice(idx, idx+nRows); idx+=nRows; }
  let out='';
  for(let r=0;r<nRows;r++) for(let c=0;c<nCols;c++) out += cols[c][r];
  return out.replace(/X+$/,'');
}

/* ---------- Registry ---------- */
const CIPHERS = {
  caesar:      { name:'Caesar Cipher', family:'Substitution', enc:caesarEncrypt, dec:caesarDecrypt,
                 hint:'An integer shift, e.g. 5', keyType:'int', example:{text:'NETWORK SECURITY', key:'5'} },
  mono:        { name:'Monoalphabetic Cipher', family:'Substitution', enc:monoEncrypt, dec:monoDecrypt,
                 hint:'A 26-letter permutation of A–Z, or press Auto', keyType:'mono', example:{text:'HELLO WORLD', key:generateMonoKey()} },
  playfair:    { name:'Playfair Cipher', family:'Substitution', enc:playfairEncrypt, dec:playfairDecrypt,
                 hint:'A keyword, e.g. MONARCHY', keyType:'text', example:{text:'HELLO WORLD', key:'MONARCHY'} },
  hill:        { name:'Hill Cipher', family:'Substitution', enc:hillEncrypt, dec:hillDecrypt,
                 hint:'Exactly 4 letters forming a 2×2 matrix, e.g. HILL (must be invertible mod 26)', keyType:'text', example:{text:'ACT', key:'HILL'} },
  vigenere:    { name:'Vigenère (Polyalphabetic) Cipher', family:'Substitution', enc:vigenereEncrypt, dec:vigenereDecrypt,
                 hint:'A keyword, e.g. LEMON', keyType:'text', example:{text:'NETWORK SECURITY', key:'LEMON'} },
  otp:         { name:'One-Time Pad', family:'Substitution', enc:otpEncrypt, dec:otpDecrypt,
                 hint:'Letters only, at least as long as the text, or press Auto', keyType:'otp', example:{text:'NETWORK SECURITY', key:generateOtpKey(16)} },
  railfence:   { name:'Rail Fence Cipher', family:'Transposition', enc:railfenceEncrypt, dec:railfenceDecrypt,
                 hint:'An integer number of rails, e.g. 3', keyType:'int', example:{text:'WEAREDISCOVEREDFLEEATONCE', key:'3'} },
  columnar:    { name:'Columnar Transposition Cipher', family:'Transposition', enc:columnarEncrypt, dec:columnarDecrypt,
                 hint:'A keyword, e.g. ZEBRA', keyType:'text', example:{text:'WEAREDISCOVEREDFLEEATONCE', key:'ZEBRA'} },
};

/* ======================================================================
   PROCESS VISUALIZERS — build HTML describing how each cipher worked
====================================================================== */
function escapeHtml(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function perCharStepsHtml(text, key, mode, cipherId){
  const MAX = 60;
  const shown = text.length > MAX ? text.slice(0,MAX) : text;
  let rows = '';
  let k = 0;
  for(let i=0;i<shown.length;i++){
    const ch = shown[i];
    if(!isAlpha(ch)){
      rows += `<tr><td>${i+1}</td><td class="plain">${escapeHtml(ch)}</td><td>—</td><td class="arrow">→</td><td class="cipher">${escapeHtml(ch)}</td><td>unchanged</td></tr>`;
      continue;
    }
    let keyChar, shift, outCh, detail;
    const upperCh = ch.toUpperCase();
    const base = isUpper(ch)?65:97;
    if(cipherId==='caesar'){
      shift = ((parseInt(key,10)%26)+26)%26;
      keyChar = key;
      outCh = mode==='E' ? caesarEncrypt(ch,key) : caesarDecrypt(ch,key);
      detail = mode==='E' ? `(${upperCh.charCodeAt(0)-65} + ${shift}) mod 26` : `(${upperCh.charCodeAt(0)-65} − ${shift}) mod 26`;
    } else if(cipherId==='vigenere'){
      const kc = key.toUpperCase().replace(/[^A-Z]/g,'')[k%key.replace(/[^A-Za-z]/g,'').length];
      keyChar = kc;
      shift = kc.charCodeAt(0)-65;
      outCh = mode==='E' ? vigenereEncrypt(ch,kc) : vigenereDecrypt(ch,kc);
      detail = mode==='E' ? `+${shift} (key '${kc}')` : `−${shift} (key '${kc}')`;
      k++;
    } else if(cipherId==='otp'){
      const kc = key.toUpperCase()[k];
      keyChar = kc;
      shift = kc ? kc.charCodeAt(0)-65 : '?';
      outCh = mode==='E' ? otpEncrypt(ch,kc||'A') : otpDecrypt(ch,kc||'A');
      detail = mode==='E' ? `+${shift} (pad '${kc}')` : `−${shift} (pad '${kc}')`;
      k++;
    } else if(cipherId==='mono'){
      keyChar = mode==='E' ? key.toUpperCase()[A.indexOf(upperCh)] : A[key.toUpperCase().indexOf(upperCh)];
      outCh = mode==='E' ? monoEncrypt(ch,key) : monoDecrypt(ch,key);
      detail = mode==='E' ? `${upperCh} maps to ${keyChar}` : `${upperCh} maps back to ${keyChar}`;
    }
    rows += `<tr><td>${i+1}</td><td class="plain">${escapeHtml(mode==='E'?ch:'')}${mode==='D'?escapeHtml(ch):''}</td><td>${keyChar||'—'}</td><td class="arrow">→</td><td class="cipher">${escapeHtml(outCh)}</td><td>${detail}</td></tr>`;
  }
  const truncNote = text.length>MAX ? `<div class="steps-note">Showing the first ${MAX} of ${text.length} characters.</div>` : '';
  const inputLabel = mode==='E' ? 'Plain' : 'Cipher';
  const outputLabel = mode==='E' ? 'Cipher' : 'Plain';
  return `<div class="steps-scroll"><table class="steps-table"><thead><tr><th>#</th><th>${inputLabel}</th><th>Key</th><th></th><th>${outputLabel}</th><th>Working</th></tr></thead><tbody>${rows}</tbody></table></div>${truncNote}`;
}

function playfairProcessHtml(text, key, mode){
  const matrix = playfairMatrix(key);
  let matrixHtml = '<table class="grid-viz">';
  for(let r=0;r<5;r++){
    matrixHtml += '<tr>';
    for(let c=0;c<5;c++) matrixHtml += `<td>${matrix[r][c]}</td>`;
    matrixHtml += '</tr>';
  }
  matrixHtml += '</table>';

  let pairs, rows='';
  if(mode==='E'){
    pairs = playfairPairs(text);
    for(const [a,b] of pairs){
      const [r1,c1]=findPos(matrix,a), [r2,c2]=findPos(matrix,b);
      let rule, out;
      if(r1===r2){ rule='Same row → shift right'; out = matrix[r1][(c1+1)%5]+matrix[r2][(c2+1)%5]; }
      else if(c1===c2){ rule='Same column → shift down'; out = matrix[(r1+1)%5][c1]+matrix[(r2+1)%5][c2]; }
      else { rule='Rectangle → swap columns'; out = matrix[r1][c2]+matrix[r2][c1]; }
      rows += `<tr><td class="plain">${a}${b}</td><td>${rule}</td><td class="arrow">→</td><td class="cipher">${out}</td></tr>`;
    }
  } else {
    const clean = text.toUpperCase().replace(/[^A-Z]/g,'');
    pairs = [];
    for(let i=0;i<clean.length-1;i+=2) pairs.push([clean[i],clean[i+1]]);
    for(const [a,b] of pairs){
      const [r1,c1]=findPos(matrix,a), [r2,c2]=findPos(matrix,b);
      let rule, out;
      if(r1===r2){ rule='Same row → shift left'; out = matrix[r1][(c1+4)%5]+matrix[r2][(c2+4)%5]; }
      else if(c1===c2){ rule='Same column → shift up'; out = matrix[(r1+4)%5][c1]+matrix[(r2+4)%5][c2]; }
      else { rule='Rectangle → swap columns'; out = matrix[r1][c2]+matrix[r2][c1]; }
      rows += `<tr><td class="plain">${a}${b}</td><td>${rule}</td><td class="arrow">→</td><td class="cipher">${out}</td></tr>`;
    }
  }
  return `<div class="matrix-block">
    <div><div class="steps-note" style="margin:0 0 4px;">5×5 key square</div>${matrixHtml}</div>
    <div style="flex:1;min-width:220px;"><div class="steps-note" style="margin:0 0 4px;">Digraph transformations</div>
    <div class="steps-scroll"><table class="steps-table"><thead><tr><th>Pair</th><th>Rule</th><th></th><th>Result</th></tr></thead><tbody>${rows}</tbody></table></div></div>
  </div>`;
}

function hillProcessHtml(text, key, mode){
  const m = hillMatrix(key);
  const matrixHtml = `<table class="grid-viz"><tr><td>${m[0][0]}</td><td>${m[0][1]}</td></tr><tr><td>${m[1][0]}</td><td>${m[1][1]}</td></tr></table>`;
  let clean = text.toUpperCase().replace(/[^A-Z]/g,'');
  let rows='';
  if(mode==='E'){
    if(clean.length%2!==0) clean+='X';
    for(let i=0;i<clean.length;i+=2){
      const p1=clean.charCodeAt(i)-65, p2=clean.charCodeAt(i+1)-65;
      const c1=(m[0][0]*p1+m[0][1]*p2)%26, c2=(m[1][0]*p1+m[1][1]*p2)%26;
      rows += `<tr><td class="plain">${clean[i]}${clean[i+1]}</td><td>[${m[0][0]}·${p1}+${m[0][1]}·${p2}, ${m[1][0]}·${p1}+${m[1][1]}·${p2}] mod 26</td><td class="arrow">→</td><td class="cipher">${String.fromCharCode(c1+65)}${String.fromCharCode(c2+65)}</td></tr>`;
    }
  } else {
    const det = (((m[0][0]*m[1][1]-m[0][1]*m[1][0])%26)+26)%26;
    const detInv = modInverse(det,26);
    const inv = [[ (m[1][1]*detInv)%26, ((-m[0][1]*detInv)%26+26)%26 ],[ ((-m[1][0]*detInv)%26+26)%26, (m[0][0]*detInv)%26 ]];
    for(let i=0;i<clean.length-1;i+=2){
      const c1=clean.charCodeAt(i)-65, c2=clean.charCodeAt(i+1)-65;
      const p1=(inv[0][0]*c1+inv[0][1]*c2)%26, p2=(inv[1][0]*c1+inv[1][1]*c2)%26;
      rows += `<tr><td class="plain">${clean[i]}${clean[i+1]}</td><td>inverse matrix × block, mod 26</td><td class="arrow">→</td><td class="cipher">${String.fromCharCode(p1+65)}${String.fromCharCode(p2+65)}</td></tr>`;
    }
  }
  return `<div class="matrix-block">
    <div><div class="steps-note" style="margin:0 0 4px;">Key matrix (mod 26)</div>${matrixHtml}</div>
    <div style="flex:1;min-width:240px;"><div class="steps-note" style="margin:0 0 4px;">Block-by-block multiplication</div>
    <div class="steps-scroll"><table class="steps-table"><thead><tr><th>Block</th><th>Computation</th><th></th><th>Result</th></tr></thead><tbody>${rows}</tbody></table></div></div>
  </div>`;
}

function railfenceProcessHtml(text, key, mode){
  const rails = parseInt(key,10);
  let plain = mode==='E' ? text : railfenceDecrypt(text, key);
  const pattern = railfencePattern(plain.length, rails);
  let grid='<table class="grid-viz">';
  for(let r=0;r<rails;r++){
    grid+='<tr>';
    for(let i=0;i<plain.length;i++){
      if(pattern[i]===r) grid+=`<td class="hi">${plain[i]}</td>`;
      else grid+=`<td class="empty">·</td>`;
    }
    grid+='</tr>';
  }
  grid+='</table>';
  const readOrder = mode==='E'
    ? 'Ciphertext = read each rail left to right, top rail to bottom rail.'
    : 'Plaintext = read the zig-zag path through the rails, in this order.';
  return `<div class="steps-note" style="margin-bottom:6px;">Zig-zag pattern across ${rails} rails</div>${grid}<div class="steps-note">${readOrder}</div>`;
}

function columnarProcessHtml(text, key, mode){
  const nCols = key.length;
  let clean = mode==='E' ? text.replace(/ /g,'') : null;
  let padded, grid, order = columnOrder(key);
  let html = '';
  if(mode==='E'){
    const nRows = Math.ceil(clean.length/nCols);
    padded = clean.padEnd(nRows*nCols,'X');
    grid=[];
    for(let r=0;r<nRows;r++) grid.push(padded.slice(r*nCols,r*nCols+nCols));
    let tbl = '<table class="grid-viz"><tr>';
    key.split('').forEach((ch,i)=>tbl+=`<td class="hi2">${ch}<br><span style="font-size:9px;">${order.indexOf(i)+1}</span></td>`);
    tbl+='</tr>';
    for(const row of grid){ tbl+='<tr>'; for(const c of row) tbl+=`<td>${c}</td>`; tbl+='</tr>'; }
    tbl+='</table>';
    html = `<div class="steps-note" style="margin-bottom:6px;">Grid filled row-by-row (key letters show read-order rank)</div>${tbl}<div class="steps-note">Columns are then read out in alphabetical-key order to form the ciphertext.</div>`;
  } else {
    const nRows = Math.ceil(text.length/nCols);
    const cols = {}; let idx=0;
    for(const col of order){ cols[col]=text.slice(idx, idx+nRows); idx+=nRows; }
    let tbl = '<table class="grid-viz"><tr>';
    key.split('').forEach((ch,i)=>tbl+=`<td class="hi2">${ch}<br><span style="font-size:9px;">${order.indexOf(i)+1}</span></td>`);
    tbl+='</tr>';
    for(let r=0;r<nRows;r++){ tbl+='<tr>'; for(let c=0;c<nCols;c++) tbl+=`<td>${cols[c][r]||''}</td>`; tbl+='</tr>'; }
    tbl+='</table>';
    html = `<div class="steps-note" style="margin-bottom:6px;">Ciphertext is poured back into columns in key order, then read row-by-row</div>${tbl}`;
  }
  return html;
}

function buildProcessHtml(cipherId, text, key, mode){
  try{
    if(['caesar','vigenere','otp','mono'].includes(cipherId)) return perCharStepsHtml(text,key,mode,cipherId);
    if(cipherId==='playfair') return playfairProcessHtml(text,key,mode);
    if(cipherId==='hill') return hillProcessHtml(text,key,mode);
    if(cipherId==='railfence') return railfenceProcessHtml(text,key,mode);
    if(cipherId==='columnar') return columnarProcessHtml(text,key,mode);
  }catch(e){
    return `<div class="steps-note">Could not render process view: ${escapeHtml(e.message)}</div>`;
  }
  return '<div class="steps-note">No process view available for this cipher.</div>';
}

/* ======================================================================
   UI WIRING — Workspace
====================================================================== */
let currentMode = 'E';

function populateCipherSelect(selectEl){
  selectEl.innerHTML = '';
  Object.entries(CIPHERS).forEach(([id,c])=>{
    const opt = document.createElement('option');
    opt.value = id; opt.textContent = c.name;
    selectEl.appendChild(opt);
  });
}

function setMode(m){
  currentMode = m;
  document.getElementById('modeEncryptBtn').classList.toggle('active', m==='E');
  document.getElementById('modeDecryptBtn').classList.toggle('active', m==='D');
  document.getElementById('outputEyebrow').textContent = m==='E' ? 'Encrypted text' : 'Decrypted text';
  document.getElementById('processToggleLabel').textContent = m==='E' ? 'Show encryption process' : 'Show decryption process';
  hideProcess();
}

function onCipherChange(){
  const id = document.getElementById('cipherSelect').value;
  document.getElementById('keyHint').textContent = CIPHERS[id].hint;
  const auto = document.getElementById('autoKeyBtn');
  auto.style.display = (id==='mono' || id==='otp') ? 'inline-block' : 'none';
  hideProcess();
}

function autoGenerateKey(){
  const id = document.getElementById('cipherSelect').value;
  const text = document.getElementById('textInput').value;
  if(id==='mono') document.getElementById('keyInput').value = generateMonoKey();
  else if(id==='otp'){
    const lettersNeeded = (text.match(/[a-zA-Z]/g)||[]).length || 8;
    document.getElementById('keyInput').value = generateOtpKey(lettersNeeded);
  }
}

function showError(el, msg){ el.textContent = msg; el.style.display='block'; }
function hideError(el){ el.style.display='none'; el.textContent=''; }

function runCipher(){
  const errorBox = document.getElementById('errorBox');
  hideError(errorBox);
  const id = document.getElementById('cipherSelect').value;
  const key = document.getElementById('keyInput').value.trim();
  const text = document.getElementById('textInput').value;
  const cipher = CIPHERS[id];
  const modeUsed = currentMode; // capture the mode this run was executed in,
                                 // since it may change below (auto-transfer to Decrypt)

  if(!key){ showError(errorBox, 'Please enter a key (or press Auto if available).'); return; }

  try{
    const start = performance.now();
    const output = modeUsed==='E' ? cipher.enc(text,key) : cipher.dec(text,key);
    const elapsed = performance.now() - start;

    document.getElementById('outputText').textContent = output || '(empty)';
    document.getElementById('execTime').textContent = elapsed < 0.01 ? '<0.01 ms' : elapsed.toFixed(3)+' ms';
    document.getElementById('charCount').textContent = text.length;
    document.getElementById('keyUsedChip').textContent = key;

    /* ----------------------------------------------------------------
       AUTO-TRANSFER: after a successful Encrypt run, carry the
       ciphertext into the same text field used for decryption and
       flip the workspace into Decrypt mode. The cipher and key stay
       exactly as they are (same select, same key field), so both are
       automatically available for the follow-up decrypt. Decryption
       itself is NOT triggered here — runCipher() is not called again —
       the user must press Run/Decrypt manually.
       Independent decryption (typing ciphertext + key directly while
       already in Decrypt mode) never enters this block, so it is
       completely unaffected.
    ---------------------------------------------------------------- */
    if(modeUsed === 'E'){
      document.getElementById('textInput').value = output;
      setMode('D'); // updates toggle buttons/labels; also clears the process panel below
    }

    // Built (or rebuilt, if setMode just cleared it above) using the mode
    // that actually produced this output, so the process view always
    // matches what just ran.
    document.getElementById('processContent').innerHTML = buildProcessHtml(id, text, key, modeUsed);
  }catch(e){
    showError(errorBox, e.message);
    document.getElementById('outputText').textContent = 'Output will appear here once you run a cipher.';
    document.getElementById('execTime').textContent = '—';
  }
}

function clearWorkspace(){
  document.getElementById('textInput').value = '';
  document.getElementById('keyInput').value = '';
  document.getElementById('outputText').textContent = 'Output will appear here once you run a cipher.';
  document.getElementById('execTime').textContent = '—';
  document.getElementById('charCount').textContent = '—';
  document.getElementById('keyUsedChip').textContent = '—';
  hideProcess();
  hideError(document.getElementById('errorBox'));
}

function copyOutput(){
  const txt = document.getElementById('outputText').textContent;
  if(!txt || txt.startsWith('Output will')) return;
  navigator.clipboard.writeText(txt).catch(()=>{});
  const btn = event.target;
  const orig = btn.textContent;
  btn.textContent = 'Copied ✓';
  setTimeout(()=>btn.textContent=orig, 1200);
}

function toggleProcess(){
  const body = document.getElementById('processBody');
  body.classList.toggle('open');
}
function hideProcess(){
  document.getElementById('processBody').classList.remove('open');
  document.getElementById('processContent').innerHTML = '';
}

/* ======================================================================
   UI WIRING — Compare
====================================================================== */
function runCompare(){
  const text = document.getElementById('compareInput').value;
  const rows = Object.entries(CIPHERS).map(([id,c])=>{
    let key;
    if(id==='mono') key = generateMonoKey();
    else if(id==='otp') key = generateOtpKey(Math.max((text.match(/[a-zA-Z]/g)||[]).length,1));
    else if(id==='hill') key = 'HILL';
    else if(id==='railfence') key = '3';
    else if(id==='caesar') key = '3';
    else key = 'KEY';
    let cipherText='', time=0, ok=true;
    try{
      const start = performance.now();
      cipherText = c.enc(text, key);
      time = performance.now()-start;
    }catch(e){ cipherText = 'Error: '+e.message; ok=false; }
    return {name:c.name, key, cipherText, time, ok};
  });
  const maxTime = Math.max(...rows.map(r=>r.time), 0.001);
  const tbody = document.getElementById('compareTableBody');
  tbody.innerHTML = rows.map(r=>`
    <tr>
      <td class="cipher-cell">${r.name}</td>
      <td class="mono">${escapeHtml(r.key)}</td>
      <td class="mono" style="color:${r.ok?'var(--parchment)':'var(--red)'};">${escapeHtml(r.cipherText)}</td>
      <td>
        <div class="time-bar-wrap">
          <div class="time-bar-track"><div class="time-bar" style="width:${Math.max((r.time/maxTime)*100,4)}%;"></div></div>
          <span class="time-label">${r.time<0.01?'<0.01':r.time.toFixed(3)} ms</span>
        </div>
      </td>
    </tr>`).join('');
  document.getElementById('compareResultsPanel').style.display = 'block';
}

/* ======================================================================
   UI WIRING — File tools
====================================================================== */
let fileMode = 'E';
let loadedFileText = null;
let loadedFileName = 'output.txt';

function setFileMode(m){
  fileMode = m;
  document.getElementById('fileModeEncryptBtn').classList.toggle('active', m==='E');
  document.getElementById('fileModeDecryptBtn').classList.toggle('active', m==='D');
  document.getElementById('fileResultPanel').style.display='none';
}

function onFileCipherChange(){
  const id = document.getElementById('fileCipherSelect').value;
  document.getElementById('fileKeyHint').textContent = CIPHERS[id].hint;
}

function autoGenerateFileKey(){
  const id = document.getElementById('fileCipherSelect').value;
  if(id==='mono') document.getElementById('fileKeyInput').value = generateMonoKey();
  else if(id==='otp'){
    const len = loadedFileText ? (loadedFileText.match(/[a-zA-Z]/g)||[]).length : 16;
    document.getElementById('fileKeyInput').value = generateOtpKey(len||16);
  }
}

function handleFile(file){
  if(!file) return;
  loadedFileName = file.name;
  const reader = new FileReader();
  reader.onload = e=>{
    loadedFileText = e.target.result;
    document.getElementById('fileNameChip').innerHTML = `<span class="filename-chip">${escapeHtml(file.name)} — ${loadedFileText.length} chars</span>`;
  };
  reader.readAsText(file);
}

function runFileCipher(){
  const errorBox = document.getElementById('fileErrorBox');
  hideError(errorBox);
  if(!loadedFileText){ showError(errorBox, 'Please choose a .txt file first.'); return; }
  const id = document.getElementById('fileCipherSelect').value;
  const key = document.getElementById('fileKeyInput').value.trim();
  if(!key){ showError(errorBox, 'Please enter a key (or press Auto if available).'); return; }
  const cipher = CIPHERS[id];
  try{
    const start = performance.now();
    const output = fileMode==='E' ? cipher.enc(loadedFileText,key) : cipher.dec(loadedFileText,key);
    const elapsed = performance.now()-start;
    document.getElementById('fileOutputPreview').textContent = output.length>500 ? output.slice(0,500)+'…' : (output||'(empty)');
    document.getElementById('fileExecTime').textContent = elapsed<0.01?'<0.01 ms':elapsed.toFixed(3)+' ms';
    document.getElementById('fileResultPanel').style.display='block';

    const blob = new Blob([output], {type:'text/plain'});
    const url = URL.createObjectURL(blob);
    const dlBtn = document.getElementById('downloadBtn');
    dlBtn.onclick = ()=>{
      const a = document.createElement('a');
      a.href = url;
      a.download = (fileMode==='E'?'encrypted_':'decrypted_') + loadedFileName;
      a.click();
    };
  }catch(e){
    showError(errorBox, e.message);
    document.getElementById('fileResultPanel').style.display='none';
  }
}

/* ======================================================================
   NAVIGATION
====================================================================== */
function goTo(viewId){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById('view-'+viewId).classList.add('active');
  document.querySelectorAll('nav.mainnav button').forEach(b=>{
    b.classList.toggle('active', b.dataset.view===viewId);
  });
  document.getElementById('mainNav').classList.remove('open');
  window.scrollTo({top:0, behavior:'smooth'});
}

/* ======================================================================
   ALGORITHM INFO CONTENT
====================================================================== */
const INFO = [
  { id:'caesar', title:'Caesar Cipher', family:'Substitution', tags:['Monoalphabetic','Symmetric-key','Ancient Rome'],
    body:`Every letter of the plaintext is shifted a fixed number of places down the alphabet. Julius Caesar reportedly used a shift of 3 to communicate with his generals. With only 25 possible keys, it's trivial to break by brute force.`,
    example:'Plain: NETWORK SECURITY, Key: 5 → Cipher: SJYBTWP XJHZWNYD' },
  { id:'mono', title:'Monoalphabetic Cipher', family:'Substitution', tags:['26! possible keys','Frequency-analysis vulnerable'],
    body:`Each letter of the alphabet is mapped to a unique, randomly chosen substitute letter, fixed for the whole message. Vastly more keys than Caesar (26! ≈ 4×10²⁶), but still breakable through letter-frequency analysis since language patterns survive the substitution.`,
    example:'Key: a full 26-letter permutation, e.g. QWERTYUIOPASDFGHJKLZXCVBNM' },
  { id:'playfair', title:'Playfair Cipher', family:'Substitution (digraph)', tags:['5×5 key square','Encrypts pairs of letters'],
    body:`Letters are encrypted two at a time using a 5×5 grid built from a keyword (I/J share a cell). Rules for row-match, column-match, and rectangle pairs determine the ciphertext pair. Invented by Charles Wheatstone in 1854, it was used by the British Army in WWI.`,
    example:'Key square from MONARCHY, pair "HE" → row/column/rectangle rule applied' },
  { id:'hill', title:'Hill Cipher', family:'Substitution (matrix)', tags:['Linear algebra','Block cipher'],
    body:`Plaintext letters are grouped into vectors and multiplied by a key matrix modulo 26. The 2×2 version used here needs a key matrix whose determinant is coprime with 26, so it has a modular inverse for decryption. Invented by Lester Hill in 1929 — one of the first ciphers built on serious mathematics.`,
    example:'Key HILL → matrix [[7,8],[11,11]], multiplies each 2-letter block mod 26' },
  { id:'vigenere', title:'Vigenère (Polyalphabetic) Cipher', family:'Substitution (polyalphabetic)', tags:['Repeating keyword','Resisted attack for 300 years'],
    body:`A keyword is repeated to align with the plaintext, and each letter is shifted by the corresponding key letter's alphabet position — effectively a Caesar cipher whose shift changes every letter. Known as "le chiffre indéchiffrable" until Kasiski and Babbage found ways to break it in the 1800s.`,
    example:'Plain: NETWORK SECURITY, Key: LEMON → Cipher: YIFKBCO ESPFVUHL' },
  { id:'otp', title:'One-Time Pad', family:'Substitution (perfect secrecy)', tags:['Information-theoretically secure','Key = length of message'],
    body:`Each letter is combined with a truly random key letter at least as long as the message, used only once. Proven unbreakable when the key is genuinely random, kept secret, and never reused — the catch is securely sharing a key as long as the message itself.`,
    example:'Key must be ≥ plaintext length; reusing a pad breaks the security guarantee entirely' },
  { id:'railfence', title:'Rail Fence Cipher', family:'Transposition', tags:['Zig-zag pattern','No letters changed, only reordered'],
    body:`Letters are written in a zig-zag across a chosen number of "rails" and then read off row by row. It doesn't change any letter's identity, only its position, making it vulnerable to simple pattern analysis once the rail count is guessed.`,
    example:'Plain: WEAREDISCOVEREDFLEEATONCE, Rails: 3' },
  { id:'columnar', title:'Columnar Transposition Cipher', family:'Transposition', tags:['Keyword-ordered columns','Often combined with substitution'],
    body:`Plaintext fills a grid row by row under a keyword; columns are then read off in the alphabetical order of the keyword's letters. Historically often layered on top of a substitution cipher (as in the WWII-era ADFGVX cipher) to add an extra layer of confusion.`,
    example:'Plain: WEAREDISCOVEREDFLEEATONCE, Key: ZEBRA' },
];

function buildInfoAccordion(){
  const container = document.getElementById('infoAccordion');
  container.innerHTML = INFO.map((item,i)=>`
    <div class="accordion-item" id="acc-${item.id}">
      <div class="accordion-head" onclick="toggleAccordion('${item.id}')">
        <h3><span class="idx">${String(i+1).padStart(2,'0')}</span> ${item.title}</h3>
        <span class="chev">▾</span>
      </div>
      <div class="accordion-body">
        <div class="accordion-body-inner">
          <div class="tag-row"><span class="tag">${item.family}</span>${item.tags.map(t=>`<span class="tag">${t}</span>`).join('')}</div>
          <p>${item.body}</p>
          <div class="example">${item.example}</div>
        </div>
      </div>
    </div>`).join('');
}
function toggleAccordion(id){
  document.getElementById('acc-'+id).classList.toggle('open');
}

/* ======================================================================
   CIPHER DISK (decorative, home hero)
====================================================================== */
function buildDisk(){
  const outer = document.getElementById('outerLetters');
  const inner = document.getElementById('innerLetters');
  for(let i=0;i<26;i++){
    const angle = (i/26)*2*Math.PI - Math.PI/2;
    const ox = 200 + 165*Math.cos(angle), oy = 200 + 165*Math.sin(angle);
    const ix = 200 + 112*Math.cos(angle), iy = 200 + 112*Math.sin(angle);
    outer.innerHTML += `<text x="${ox}" y="${oy}" text-anchor="middle" dominant-baseline="middle">${A[i]}</text>`;
    inner.innerHTML += `<text x="${ix}" y="${iy}" text-anchor="middle" dominant-baseline="middle">${A[(i+5)%26]}</text>`;
  }
}

/* ======================================================================
   INIT — runs once, after a successful login
====================================================================== */
let appInitialized = false;
function initApp(){
  if(appInitialized) return;   // never wire things up twice
  appInitialized = true;

  document.querySelectorAll('nav.mainnav button').forEach(btn=>{
    btn.addEventListener('click', ()=>goTo(btn.dataset.view));
  });
  document.getElementById('hamburgerBtn').addEventListener('click', ()=>{
    document.getElementById('mainNav').classList.toggle('open');
  });

  const fileInput = document.getElementById('fileInput');
  fileInput.addEventListener('change', e=>handleFile(e.target.files[0]));
  const dropzone = document.getElementById('dropzone');
  ['dragover','dragenter'].forEach(evt=>dropzone.addEventListener(evt, e=>{ e.preventDefault(); dropzone.classList.add('drag'); }));
  ['dragleave','drop'].forEach(evt=>dropzone.addEventListener(evt, e=>{ e.preventDefault(); dropzone.classList.remove('drag'); }));
  dropzone.addEventListener('drop', e=>{ if(e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); });

  populateCipherSelect(document.getElementById('cipherSelect'));
  populateCipherSelect(document.getElementById('fileCipherSelect'));
  onCipherChange();
  onFileCipherChange();
  buildInfoAccordion();
  buildDisk();
}

/* ======================================================================
   LOGIN GATE
   Client-side password check. Note: this is NOT real security — anyone
   can read the password out of this JS file. It's a simple access gate
   for a mini project demo, not a substitute for server-side auth.
====================================================================== */
const TOOLKIT_PASSWORD = 'cipher123'; // change this to your own password
const MAX_ATTEMPTS = 5;
let loginAttempts = 0;

function attemptLogin(){
  const input = document.getElementById('loginPassword');
  const errorEl = document.getElementById('loginError');
  const value = input.value;

  if(value === TOOLKIT_PASSWORD){
    document.getElementById('loginGate').classList.add('hidden');
    document.getElementById('appRoot').classList.add('unlocked');
    try{ sessionStorage.setItem('toolkitUnlocked', 'yes'); }catch(e){ /* storage unavailable — ignore */ }
    initApp();
  } else {
    loginAttempts++;
    input.value = '';
    input.focus();
    if(loginAttempts >= MAX_ATTEMPTS){
      errorEl.textContent = 'Too many incorrect attempts. Reload the page to try again.';
      document.getElementById('loginSubmit').disabled = true;
      input.disabled = true;
    } else {
      errorEl.textContent = `Incorrect password. ${MAX_ATTEMPTS - loginAttempts} attempt(s) left.`;
    }
  }
}

document.getElementById('loginSubmit').addEventListener('click', attemptLogin);
document.getElementById('loginPassword').addEventListener('keydown', e=>{
  if(e.key === 'Enter') attemptLogin();
});

/* Skip the login screen if already unlocked earlier in this browser tab's session */
let alreadyUnlocked = false;
try{ alreadyUnlocked = sessionStorage.getItem('toolkitUnlocked') === 'yes'; }catch(e){ /* storage unavailable — ignore */ }

if(alreadyUnlocked){
  document.getElementById('loginGate').classList.add('hidden');
  document.getElementById('appRoot').classList.add('unlocked');
  initApp();
} else {
  document.getElementById('loginPassword').focus();
}
