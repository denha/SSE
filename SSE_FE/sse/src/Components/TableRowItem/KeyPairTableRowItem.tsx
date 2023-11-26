import React from "react";
import { keypairProp } from "../../types";

const KeyPairTableRowItem = ({keypair}:any)=>{

const {cname,ounit,location,state,country,organ,keystore_name,validity}= keypair
return <tr>
    <td scope="col">{keystore_name}</td>
    <td>{cname}</td>
    <td>{ounit}</td>
    <td>{location}</td>
    <td>{state}</td>
    <td>{country}</td>
    <td>{organ}</td>
    <td>{validity}</td>
    </tr>
}

export default KeyPairTableRowItem