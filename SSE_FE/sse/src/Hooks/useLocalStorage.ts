import { useState } from "react"

export const useLocalStorage = ()=>{

    const [value,setValue]= useState<string|null>(null)
    const addItem = (key:string,value:string)=>{
        localStorage.setItem(key,value)
        setValue(value)
    }

    const getItem =(key:string)=>{
        const value = localStorage.getItem(key)
        setValue(value)
        return value;
        
    }

    const removeItem=(key:string)=>{
        const value = localStorage.removeItem(key)
        setValue(null)

    }


    return {addItem,getItem,removeItem}

}