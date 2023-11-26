import React from 'react'

const TableRow= ({items,DataResource,DataComponent}:any)=>{
    //items = items.length>0 ?items: []
return <>
{items?.map((item:any)=>(
 
<DataComponent key={item.id} {...{[DataResource]:item}} />
))}
</>
}

export default TableRow