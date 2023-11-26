import axios, { AxiosProgressEvent } from "axios";
import { truncate } from "fs/promises";
import { useEffect, useState } from "react";
type method = 'POST'|'PUT'|'DELETE'|'GET'

const useAPI =()=>{


const [data,setData]= useState([]);
const [loading,setLoading]=useState(true)
const [error,setError]=useState<string>()
const [dataOwner,setDataOwner]=useState([])
const [secretKey,setSecretKey]=useState()
const [secret,setSecret]=useState({kg:'',kske:''})
const [uploadProgress, setUploadProgress] = useState<number>(0);



const postData = async(method:method,url:string,body?:any)=>{

            try{
                const results = await request(method,url,body)
                if(results?.status===200 || results?.status ===201){
                    if (url.includes('check-secret-key')){
                        setSecretKey(results.data.data)
                     }
                     else if(url.includes("KG")){
                        setSecret({...secret,kg:results.data.data})
                    }
                    else if(url.includes("generate-secret-key/KSKE")){
                        setSecret({...secret,kske:results.data.data})
                    }else{
                        setData(results.data.data)
                     }
                    setLoading(false)
                }
                
            }catch(e){
            if(e instanceof Error)
                setError(e.message)
                setLoading(false)
                
            }

        //}


}

const fetchData = async(url:string,param?:string)=>{
    try{
        const multipleUrl = url.split(',')
        if(multipleUrl.length>1){
            const [request1,request2] = await multipleRequest("GET",url)
            setSecret({kg:request1.data.data,kske:request2.data.data})
        }
        if(url.includes('download') || url.includes('decrypt')){
            const result = await downloadRequest('GET',url)
            return;
        }
        
        if(multipleUrl.length===1){
            const results = await request('GET',url,param)
            if(results?.status===200){
                if(url.includes('data-owner')){
                    setDataOwner(results.data.data)
                }
                else if (url.includes('check-secret-key')){
                   setSecretKey(results.data.data)
                }
                else if (url.includes('fetch-files')){
                    const unModFiles = results.data.data;
                    //const modFiles = unModFiles.unshift({'name':'All Files','checked':false,'id':'all'})
                    //console.log(unModFiles)
                    setData(results.data.data) 
                    let allFiles:any = []
                    results.data.data?.forEach((file:any)=>{
                        allFiles.push({'name':file.name,'checked':true,'id':file.name})
                        
                    })
                    //allFiles.push({'name':'all','checked':false,'id':'all'})
                    localStorage.setItem('files', JSON.stringify(allFiles));
                    
                 }
                else if(param!=="No"){
                    setData(results.data.data)    
                }
                else{
                    setData(results.data.data)
                 }
    
                setLoading(false)
    
            }

        }


    }catch(e){
        if(e instanceof Error)
        setError(e.message)
        setLoading(false)
        
    }
    }



const request =async(method:method,url:string,body?:any)=>{
    if(method==='POST'){
        return await axios.post(url,body)
    }
    else if(method==='GET'){
        return await axios.get(url)
    }
    
}

const multipleRequest = async(method:method,url:string,body?:any)=>{
    const urls = url.split(',')
    const request1= axios.get(urls[0])
    const request2= axios.get(urls[1])
    return await Promise.all([request1, request2]);

}
const downloadRequest = async(method:method,url:string)=>{
    axios({
        method: method,
        url: url,
      })
        .then(response => {
          const file = url.split('/')
          const filename = url.includes('decrypt')? file[4].slice(0,-4): file[4]
          const downloadUrl = window.URL.createObjectURL(new Blob([response.data.data]));
          const link = document.createElement('a');
          link.href = downloadUrl;
          link.setAttribute('download', filename);
          document.body.appendChild(link);
          link.click();
          link.remove();
        })
        .catch(error => {
          // Handle error
          console.log(error)
        });


}

return {error,data,loading,setLoading,postData,fetchData,uploadProgress,dataOwner,secretKey,secret}
}
export default useAPI;