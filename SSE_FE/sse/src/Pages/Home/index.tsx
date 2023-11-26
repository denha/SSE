import React, { useState } from "react";
import {CardBoard} from "../../Components/CardBoard";

import './home.css'
import upload from '../../img/upload.png';
import secretKey from '../../img/secret-key.png'
import encrypt from '../../img/encrypt.png'
import HomeDialogBox from "./HomeDialogBox";

const Home =()=>{

const [dialogValue,setDialogValue]=useState({id:'',title:''})

    return<div>
        <div className="card-container">
            <CardBoard>
                <CardBoard.Head><span>Menu</span></CardBoard.Head>
                <CardBoard.Body>
                    <div className="key-gen">
                        <CardBoard className="key-gen-card" dataToggle='modal' dataTarget='#secretkey' onClick={()=>setDialogValue({id:'secretkey',title:'Create Secret Keys'})}>
                            <img src={secretKey} width="30px" height="30px" className="key-img"/>
                            <div className="key-img-footer">
                            <p>Secret key</p>
                            </div>
                        </CardBoard>
                        <CardBoard className="key-gen-card" dataToggle='modal' dataTarget='#encrypt' onClick={()=>setDialogValue({id:'encrypt',title:'File Encryption'})}>
                            <img src={encrypt} width="30px" height="30px" className="key-img"/>
                            <div className="key-img-footer">
                            <p>File Encryption</p>
                            </div>
                        </CardBoard>
                    </div>
                    <div className="key-gen-single">
                        <CardBoard className="key-gen-card" dataToggle='modal' dataTarget='#upload' onClick={()=>setDialogValue({id:'upload',title:'File Upload'})}>
                            <img src={upload} width="30px" height="30px" className="key-img"/>
                            <div className="key-img-footer">
                            <p>File Upload</p>
                            </div>
                        </CardBoard>
                    </div>
                </CardBoard.Body>   
            </CardBoard>
            <HomeDialogBox id={dialogValue.id} title={dialogValue.title} />
        </div>
    </div>
}

export default Home