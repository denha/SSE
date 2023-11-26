import React from 'react'

const KeyPairHeader = ({headers}:any)=>{

    return <>
  <thead>
    <tr>
      <th scope="col">{headers.keystore_name}</th>
      <th scope="col">{headers.cname}</th>
      <th scope="col">{headers.ounit}</th>
      <th scope="col">{headers.location}</th>
      <th scope="col">{headers.state}</th>
      <th scope="col">{headers.country}</th>
      <th scope="col">{headers.organ}</th>
      <th scope="col">{headers.validity}</th>
    </tr>
  </thead>

    </>

}

export default KeyPairHeader;