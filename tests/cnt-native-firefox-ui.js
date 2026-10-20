// Dispatch-only synthetic UI subset. No native semantic helpers replaced.
const [mode,payload,done]=arguments; (async()=>{
const delay=ms=>new Promise(r=>setTimeout(r,ms));
for(let i=0;i<100&&!document.body.innerText.includes('Download back up');i++)await delay(100);
if(mode==='seed'){
const transfer=new DataTransfer();payload.forEach((b,i)=>transfer.items.add(new File([Uint8Array.from(atob(b),c=>c.charCodeAt(0))],`synthetic-${i}.png`,{type:'image/png',lastModified:1700000000000+i})));
const input=document.querySelector('input[type=file].input');input.files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));
await delay(2000);
const size=document.querySelector('select[name=background_size]');size.value='cover_screen';size.dispatchEvent(new Event('change',{bubbles:true}));
const editors=[...document.querySelectorAll('.CodeMirror')];const values=['<p>Synthetic CNT fixture</p>','p { color: rgb(12,34,56); }','void 0;'];for(const e of editors){e.CodeMirror.setValue(' ');await delay(300);}
for(let i=0;i<editors.length;i++){editors[i].CodeMirror.setValue(values[i]);await delay(500);}
await delay(1000);
}else if(mode==='import'){
const transfer=new DataTransfer();payload.forEach(a=>transfer.items.add(new File([a.text],a.name,{type:'application/json',lastModified:1700000000000})));
const input=document.querySelector('input.file.back_up');input.files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));
await delay(3000);
}else{throw new Error('Unknown mode');}
const blobs=new Map(),artifacts=[];const originalURL=URL.createObjectURL;URL.createObjectURL=b=>{const u=originalURL(b);blobs.set(u,b);return u;};
const originalClick=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){const b=blobs.get(this.href);if(b?.type==='application/octet-stream'){artifacts.push({name:this.download,blob:b});return;}return originalClick.call(this);};
[...document.querySelectorAll('button')].find(e=>e.innerText==='Download back up').click();
for(let i=0;i<100&&!artifacts.length;i++)await delay(100);
done({prefs:JSON.parse(JSON.stringify(data.settings.prefs)),artifacts:await Promise.all(artifacts.map(async a=>({name:a.name,text:await a.blob.text()})))});
})().catch(e=>done({error:String(e),stack:e.stack}));
