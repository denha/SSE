import React from 'react'

import { DialogBoxProp,DialogBoxHeadProp,ReactChildProp } from '../types'

export const DialogBox = ({className,id,ariaLabelledby,ariaHidden,children}:DialogBoxProp)=>{

return <div className={`modal fade ${className}`} id={id} role="dialog" aria-labelledby={ariaLabelledby} aria-hidden={ariaHidden}>
    <div className="modal-dialog modal-dialog-centered" role="document">
    <div className="modal-content">
        {children}
    </div>
    </div>
</div>
}

DialogBox.Head = ({children,title,isCloseBtn}:DialogBoxHeadProp)=>{
return <div className="modal-header">
<h5 className="modal-title" id="exampleModalLabel">{title}</h5>
{
    isCloseBtn && (<button type="button" className="close" data-dismiss="modal" aria-label="Close">
    <span aria-hidden="true">&times;</span>
  </button>)
}

</div>
}



DialogBox.Body = ({children}:ReactChildProp)=>{

    return <div className="modal-body">{children}</div>
}

DialogBox.Foot = ({children}:ReactChildProp)=>{
return <div className="modal-footer">{children}</div>
}

