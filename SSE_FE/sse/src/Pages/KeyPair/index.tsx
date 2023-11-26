import React, { useState } from 'react'

import { CardBoard } from '../../Components/CardBoard'
import { Table } from '../../Components/Table'
import {DialogBox} from '../../Components/DialogBox'
import TableRow from '../../Components/TableRow'
import KeyPairTableRowItem from '../../Components/TableRowItem/KeyPairTableRowItem'
import KeyPairHeader from '../../Components/TableRowItem/KeyPairHeader'
import Button from '../../Components/FormControl/Button'
import InputField from '../../Components/FormControl/InputField'
import { countries,yearData,tableHeader } from '../../Data/data'
import './index.css'
import { keypairProp } from '../../types'
import useAPI from '../../Hooks/useFetch'

const KeyPair = ()=>{

const [keyPair,setKeyPair]= useState<keypairProp>({id:'',validity:'',cname:'',ounit:'',location:'',state:'',country:'',organ:'',keystore_name:'CSP'})
const {data,error,postData} = useAPI()
const handleChange = (event:any)=>{
    setKeyPair({...keyPair,[event.target.name]:event.target.value})

}
let changedData = []
changedData.push(data)
const save= (event:any)=>{
postData('POST','http://127.0.0.1:8000/generate-key-pair',keyPair)
}
return<div className="card-container">
    <CardBoard>
        <CardBoard.Body>
            <div className='create-btn-container'>
                <div>
                <Button id='new' name='New' className="action" btnType='primary' small={true} type="button" dataToggle='modal' dataTarget='#createkeypairmodal'/>
                <Button id='publish' name='Publish' btnType="success" small={true} type="button" dataToggle='modal' dataTarget='#createkeypairmodal'/>
                </div>
                <DialogBox id="createkeypairmodal">
                    <DialogBox.Head  isCloseBtn={true} title='Create key pair'/>
                    <DialogBox.Body>
                        <form>
                        <InputField  id="cname" label='Common Name (CN)' type='text' name="cname" onChange={handleChange}/>
                        <InputField  id="ounit" label='Organization Unit (OU)' name="ounit" onChange={handleChange}/>
                        <InputField  id="location" label='Locality (L)' name='location' onChange={handleChange}/>
                        <InputField  id="state" label='State (ST)' name="state" onChange={handleChange}/>
                        <InputField  id="country" label='Country'  name="country" type='dropdown' data={countries} onChange={handleChange}/>
                        <InputField  id="organ" label='Organization (O)' name='organ' onChange={handleChange}/>
                        <InputField  id="validity" label='Validity' type='dropdown' name='validity' data={yearData} onChange={handleChange}/>
                        </form>
                    </DialogBox.Body>
                    <DialogBox.Foot>
                    <Button  btnType='secondary' small={true}  name='Close' id='close' type='button' data-bs-dismiss="modal"/>
                    <Button name='Save' id="save" btnType='primary' small={true} type='button' onClick={save}/>
                    </DialogBox.Foot>
                </DialogBox>
            </div>
            <Table>
            <Table.Head
                items={tableHeader}
                itemComponent={KeyPairHeader}
                itemResource="headers"               
            />
                <Table.Body>
                    <TableRow 
                    items={changedData}
                    DataResource="keypair"
                    DataComponent={KeyPairTableRowItem}    
                    />                   
                </Table.Body>

            </Table>
        </CardBoard.Body>
    </CardBoard>
    <CardBoard className='key-container'>
        <CardBoard.Head>Public Key</CardBoard.Head> 
        <CardBoard.Body>hey</CardBoard.Body>
    </CardBoard>
    <CardBoard className='key-container'>
        <CardBoard.Head>Private Key</CardBoard.Head> 
        <CardBoard.Body>hey</CardBoard.Body>
    </CardBoard>
</div>
}

export default KeyPair