() => {
  const issues=[];
  const modal=document.querySelector('dialog[open]');
  const root=modal || document;
  const visible=el=>el && el.getClientRects().length && getComputedStyle(el).visibility!=='hidden' && !el.closest('[hidden]');
  const name=el=>el.id || el.getAttribute('aria-label') || el.textContent.trim().slice(0,60) || el.tagName;
  const mobile=innerWidth<=760 || (innerWidth<=900 && innerHeight<=600);
  for(const el of document.querySelectorAll('h1,h2,h3,p,[role=heading]')) {
    if(el.hasAttribute('autofocus') || el.hasAttribute('tabindex')) issues.push({rule:'static-focus',element:name(el)});
  }
  const active=document.activeElement;
  if(active.matches('h1,h2,h3,p,[role=heading]'))issues.push({rule:'focused-prose',element:name(active)});
  if(modal && !modal.contains(active))issues.push({rule:'modal-focus-outside'});
  const focusGroup=active.closest('[data-focus-group]');
  if(focusGroup && active.matches('input')) {
    const fieldStyle=getComputedStyle(active),groupStyle=getComputedStyle(focusGroup);
    if(fieldStyle.outlineStyle!=='none' || fieldStyle.boxShadow!=='none')issues.push({rule:'duplicate-field-focus',element:name(active)});
    if(groupStyle.boxShadow==='none' && groupStyle.outlineStyle==='none')issues.push({rule:'missing-group-focus',element:name(active)});
  }
  if(active.matches('input:not([type=hidden]),textarea,button,a[href],select,summary') && active.matches(':focus-visible')) {
    let indicator=active;
    if(focusGroup && active.matches('input'))indicator=focusGroup;
    else if(active.matches('input[type=file]'))indicator=active.closest('label') || active;
    else if(active.matches('textarea'))indicator=active.closest('.text-view') || active;
    const style=getComputedStyle(indicator);
    if(style.outlineStyle==='none' && style.boxShadow==='none')issues.push({rule:'missing-focus-indicator',element:name(active)});
    const ring=style.outlineStyle!=='none'?Math.max(0,+style.outlineWidth.replace('px','') + +style.outlineOffset.replace('px','')):0;
    if(ring) {
      const r=indicator.getBoundingClientRect();
      for(let ancestor=indicator.parentElement;ancestor;ancestor=ancestor.parentElement){
        const a=getComputedStyle(ancestor),bounds=ancestor.getBoundingClientRect();
        if((['hidden','auto','scroll','clip'].includes(a.overflowX) && (r.left-ring<bounds.left-.5 || r.right+ring>bounds.right+.5)) || (['hidden','auto','scroll','clip'].includes(a.overflowY) && (r.top-ring<bounds.top-.5 || r.bottom+ring>bounds.bottom+.5))) {issues.push({rule:'clipped-focus-ring',element:name(active)});break;}
      }
    }
  }
  const controls=[];
  for(const el of root.querySelectorAll('button,a[href],input,select,textarea,label.button')) {
    if(!visible(el))continue;
    let target=el;
    if(el.matches('input[type=file],input[type=checkbox],input[type=radio]'))target=el.closest('label') || el;
    if(!visible(target))continue;
    const r=target.getBoundingClientRect(),style=getComputedStyle(target);
    controls.push({element:name(target),width:r.width,height:r.height});
    if(mobile && (r.height<43.5 || r.width<43.5))issues.push({rule:'touch-size',element:name(target),width:r.width,height:r.height});
    if(mobile && target.matches('.button') && target.innerText.trim() && (+style.paddingLeft.replace('px','')<12 || +style.paddingRight.replace('px','')<12))issues.push({rule:'button-padding',element:name(target),padding:[style.paddingLeft,style.paddingRight]});
    if(r.left<-.5 || r.right>innerWidth+.5)issues.push({rule:'horizontal-overflow',element:name(target)});
    // Inner scroll regions may contain offscreen controls; pinned primary actions may not.
    if(target.matches('#send,#copy-link') && (r.top<0 || r.bottom>innerHeight))issues.push({rule:'primary-offscreen',element:name(target)});
    if(target.matches('.button') && target.scrollWidth>target.clientWidth+1)issues.push({rule:'button-content-overflow',element:name(target)});
    if(target.matches('.button')) {
      const px=value=>+value.replace('px','');
      const area={left:r.left+px(style.borderLeftWidth)+px(style.paddingLeft),right:r.right-px(style.borderRightWidth)-px(style.paddingRight),top:r.top+px(style.borderTopWidth)+px(style.paddingTop),bottom:r.bottom-px(style.borderBottomWidth)-px(style.paddingBottom)};
      const parts=[];
      const textRects=node=>{
        if(node.nodeType===3 && node.textContent.trim() && visible(node.parentElement)) {
          const range=document.createRange();range.selectNodeContents(node);
          parts.push(...range.getClientRects());
        } else if(node.nodeType===1 && node.tagName.toLowerCase()!=='svg' && visible(node)) {
          for(const child of node.childNodes)textRects(child);
        }
      };
      textRects(target);
      for(const icon of target.querySelectorAll('svg'))if(visible(icon))parts.push(icon.getBoundingClientRect());
      if(parts.some(part=>part.left<area.left-1 || part.right>area.right+1 || part.top<area.top-1 || part.bottom>area.bottom+1))issues.push({rule:'button-content-in-padding',element:name(target),padding:[style.paddingLeft,style.paddingRight],availableWidth:area.right-area.left,contentWidth:parts.length?Math.max(...parts.map(p=>p.right))-Math.min(...parts.map(p=>p.left)):0});
    }

  }
  const editor=document.querySelector('#editor, #draft');
  if(visible(editor) && !modal && editor.getBoundingClientRect().height<48)issues.push({rule:'editor-collapsed',height:editor.getBoundingClientRect().height});
  if(document.documentElement.scrollWidth>innerWidth || document.documentElement.scrollHeight>innerHeight+1)issues.push({rule:'document-overflow'});
  return {width:innerWidth,height:innerHeight,theme:document.documentElement.dataset.theme,dialog:modal?.id || null,focus:name(active),issues,controls};
}
