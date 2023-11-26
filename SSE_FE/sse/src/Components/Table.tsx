import React from 'react'
import { ReactChildProp } from '../types'

export const Table = ({children}:ReactChildProp)=>{

    return<table className="table table-sm">
    {children}
    </table>
}

Table.Thead = ({children}:ReactChildProp)=>{
    return <thead>
        {children}
    </thead>
}

Table.Body = ({children}:ReactChildProp)=>{
    return<tbody>
        {children}
    </tbody>
}

Table.Head= ({items,itemResource,itemComponent:ItemComponent}:any)=>{
    return <>
    {
        items.map((item:any)=>(
            <ItemComponent key={item.id} {...{[itemResource]:item}} />
        ))
    }
    
    </>


}