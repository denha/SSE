import React from "react"
import { ReactChildProp } from "../types"

import  './components.css'

const Container = ({children}:ReactChildProp)=>{

return <div className="main-container">
        {children}
</div>

}

export default Container