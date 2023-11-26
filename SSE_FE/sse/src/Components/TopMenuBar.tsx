import * as React from 'react';
import { styled, alpha } from '@mui/material/styles';
import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import Toolbar from '@mui/material/Toolbar';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import InputBase from '@mui/material/InputBase';
import Badge from '@mui/material/Badge';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import MenuIcon from '@mui/icons-material/Menu';
import SearchIcon from '@mui/icons-material/Search';
import AccountCircle from '@mui/icons-material/AccountCircle';
import MailIcon from '@mui/icons-material/Mail';
import NotificationsIcon from '@mui/icons-material/Notifications';
import MoreIcon from '@mui/icons-material/MoreVert';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';

const TopMenuBar = ()=>{


      
      const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
      const [mobileMoreAnchorEl, setMobileMoreAnchorEl] =
        React.useState<null | HTMLElement>(null);
    
      const [url,setUrl]= React.useState<string>("");
      const isMenuOpen = Boolean(anchorEl);
      const navigate = useNavigate();
    
      React.useEffect(()=>{
        fetchUrl();

      },[])
      const handleProfileMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
        setAnchorEl(event.currentTarget);
      };
    
      const handleMobileMenuClose = () => {
        setMobileMoreAnchorEl(null);
      };
    
      const handleMenuClose = () => {
        setAnchorEl(null);
        handleMobileMenuClose();
      };
    
      const fetchUrl = async()=>{
        const url = "http://localhost:8000/auth/dropbox/"+localStorage.getItem('user_id');
        const results = await axios.get(url);
        if(results.status===200){
            setUrl(results.data.data)
        }

      }
    
      const handleMenu = (event: React.MouseEvent<HTMLElement>) => {
        setAnchorEl(event.currentTarget);
      };
    
      const handleClose = () => {
        setAnchorEl(null);
        localStorage.clear();
        navigate('/login')

      };

      const handleSync = ()=>{
        
      }
      const menuId = 'primary-search-account-menu';

    return (
        <Box sx={{ flexGrow: 1 }}>
          <AppBar position="static">
            
            <Toolbar>
              <IconButton
                size="large"
                edge="start"
                color="inherit"
                aria-label="open drawer"
                sx={{ mr: 2 }}
              >
                <MenuIcon />
              </IconButton>
              <Box sx={{ flexGrow: 1 }} />
              <Box sx={{ display: { xs: 'none', md: 'flex' } }}>
                <IconButton
                  size="large"
                  edge="end"
                  aria-label="account of current user"
                  aria-controls={menuId}
                  aria-haspopup="true"
                  onClick={handleProfileMenuOpen}
                  color="inherit"
                >
                  <AccountCircle />
                </IconButton>
                <Menu
                id="menu-appbar"
                anchorEl={anchorEl}
                anchorOrigin={{
                  vertical: 'top',
                  horizontal: 'right',
                }}
                keepMounted
                transformOrigin={{
                  vertical: 'top',
                  horizontal: 'right',
                }}
                open={Boolean(anchorEl)}
              >
                <MenuItem onClick={handleClose} >Log Out</MenuItem>
                <MenuItem onClick={handleSync} ><Link target='_blank' to={url}>Sync with dropbox</Link></MenuItem>

              </Menu>
              </Box>
            </Toolbar>
          </AppBar>

        </Box>
      );
}

export default TopMenuBar






