import React,{useEffect, useState} from "react";
import Button from "../../Components/FormControl/Button";
import './index.css'
import { Table } from "../../Components/Table";
import TableRow from "../../Components/TableRow";
import SearchResultsRow from "../../Components/TableRowItem/SearchResultsRow";
import useAPI from "../../Hooks/useFetch";
import { DialogBox } from "../../Components/DialogBox";
import InputField from "../../Components/FormControl/InputField";
import axios from "axios";

const Search = ()=>{

    const {data,fetchData,dataOwner,secretKey,postData} = useAPI();
    const [searchValue,setSearchValue]= useState('')
    const [dtaOwner,setDtaOwner]= useState('')
    const[dialog,setDialog]= useState(false)
    const [password,setPassword]=useState('')
    const [dismissModal,setDismissModal]= useState(false)
  
    const search = ()=>{
        if(dtaOwner==""){
            alert('Please select Data owner')
       }    
    }

    const download = (type:string)=>{
        data?.forEach((files:any)=>{
            if(type==="downloadAll"){
                fetchData(`http://127.0.0.1:8000/download/${files.results}`,"No")
                return;
            }
            fetchData(`http://127.0.0.1:8000/decrypt/${files.results}/${localStorage.getItem('selectedDataOwner')}`,"No")
        })

    }
    const handleChange = (e:any)=>{
        setDtaOwner(e.target.value)
        localStorage.setItem('selectedDataOwner',e.target.value)
    }
    useEffect(()=>{
        fetchData("http://127.0.0.1:8000/data-owner")
    },[])

   const FinalSearch = ()=>{
    const url = `http://127.0.0.1:8000/check-secret-key/KSKE/${localStorage.getItem('selectedDataOwner')}`
    axios.post(url,{key:password}).then((results)=>{

        if(results.data.data){
            fetchData(`http://127.0.0.1:8000/search/${searchValue}/${dtaOwner}`)
            setDismissModal(true)
            setPassword("")
            return;
        }else{
            alert("Incorrect password")
        }
    }).catch((error)=>{
        alert("Incorrect password")
    })

   }
    return <div className="search-container">
        <div>
        <div className="search-title">
            <h2 style={{ fontSize: '28px', fontWeight: 'bold', color: '#333', marginBottom: '10px',fontFamily: 'Arial, sans-serif' }}>Search </h2>
        </div>

        </div>
<div className="row">
  <div className="col-md-5 mx-auto">
    <div className="input-group">
      <input
        className="form-control border-end-0 border rounded-pill custom-input"
        type="search"
        onChange={(e) => setSearchValue(e.target.value)}
        placeholder="search ...."
        id="example-search-input"
      />
      <div className="input-group-append">
        <select onChange={handleChange}
          className="form-select border-start-0 border rounded-pill ms-n5 custom-input">
        {
            dataOwner?.map((owner:any)=><option  key={owner.id} value={owner.id}>{owner.value}</option>)
        }
        </select>
        <button
          className="btn btn-outline-secondary bg-white border-bottom-0 border rounded-pill ms-n5 custom-input"
          onClick={search}
          type="button"
          data-toggle='modal' 
          data-target='#passworddlg'
        >
          <i className="fa fa-search"></i>
        </button>
      </div>
    </div>
  </div>
</div>

    <div className="search-results">
        <div className="search-btn">
        {data?.length>0 && <h6>{`(${data?.length===undefined ? 'No' : data.length}) Results Found`} </h6>}
        {data?.length>0 && <div>
        <Button btnType='primary' className="search-btn-space" small={true}  onClick={()=>download('decryptAll')} id='generate' type='button'><i className="fa fa-key" aria-hidden="true"></i>
        </Button>
        <Button btnType='success' small={true} onClick={()=>download('downloadAll')} id='generate' type='button'><i className="fa fa-download" aria-hidden="true"></i>
       </Button>
        </div>}
        </div>
        
        <Table>
            <Table.Body>
                <TableRow  items={data} DataResource="search" DataComponent={SearchResultsRow}  />
            </Table.Body>
        </Table>

    </div>
        <DialogBox id="passworddlg">
            <DialogBox.Head isCloseBtn={true} title="Enter Password"/>
                <DialogBox.Body>
                <InputField  id="cname" label='Password' type='password' value={password} onChange={(e:any)=>setPassword(e.target.value)} />
                </DialogBox.Body>
                <DialogBox.Foot>
                    <Button  btnType='secondary' small={true}  name='Close' id='close' type='button'   />
                    <Button name='Search' id="save" btnType='primary' small={true} onClick={FinalSearch} dismiss={true} type='button'/>
                </DialogBox.Foot>
            </DialogBox> 
 

    </div>

}
export default Search

