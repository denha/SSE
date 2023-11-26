import { ReactNode } from "react"
import { JsxElement } from "typescript"

export type user={
key:string,
user_id:string,
email:string,
role?:string
}

export type userLoginData={
    email:string,
    password:string,
    role:string
}

export type ReactChildProp={
    children:ReactNode
}

export type CardBoardProp = {
    children:ReactNode,
    className?:string,
    onClick?:any,
    dataToggle?:string,
    dataTarget?:string,
    id?:string

}

export type CardBoardHead={
    icon?:string,
    children:ReactNode
}

export type CardBoardBodyProp={
    children:ReactNode,
    className?:string
}

export type keypairProp={
    id:string,
    validity:string,
    cname:string,
    ounit:string,
    location:string,
    state:string,
    country:string,
    organ:string,
    keystore_name:string
}

export type ButtonProp={
    id:string,
    name?:string,
    className?:string,
    type:'button'|'submit'
    dataToggle?:'modal',
    dataTarget?:string,
    small?:boolean,
    btnType?:'success'|'secondary'|'primary',
    onClick?:any,
    children?:ReactNode
    dismiss?:boolean

}

export type DialogBoxProp={
className?:string,
id:string,
ariaLabelledby?:string,
ariaHidden?:boolean,
children:ReactNode
}

export type DialogBoxHeadProp={
children?:ReactNode,
title?:string,
isCloseBtn?:boolean
}

export type InputFieldProp={
    id:string,
    name?:string,
    label?:string,
    type?:string,
    data?:any,
    onChange?:any,
    value?:string
    disabled?:boolean
}

