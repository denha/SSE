import React from "react";
import useAPI from "../../Hooks/useFetch";
import { Link } from "react-router-dom";

const  SearchResultsRow = ({search}:any)=>{
    const {fetchData} =useAPI()
    const owner = localStorage.getItem('selectedDataOwner')
    const download = (file:string)=>{
        fetchData(`http://127.0.0.1:8000/download/${file}`)

    }
    const decrypt = (file:string)=>{
        fetchData(`http://127.0.0.1:8000/decrypt/${file}/${owner}`)
    }
    return(
    <tr>
        <td>{search.id}</td><td className="table-space-file">{search.results}</td> <td className="table-space"> <a href="#" onClick={()=>download(`${search.results}`)}>Download</a></td> 
        <td className="table-space"> <a href="#" onClick={()=>decrypt(`${search.results}`)}>Decrypt</a></td> <td>
            <Link to={`/file-viewer/${search.results}`}>
      View
    </Link></td>
    </tr>)

}

export default SearchResultsRow