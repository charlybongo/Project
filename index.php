<?php
include_once('dbcon.php');
session_start();
if(isset($_POST['submit'])){
	  $user=$_POST['username'];
	  $pass=$_POST['password'];
	  $sql="SELECT * FROM registration WHERE username='$user' AND password='$pass'";
	  $query=mysqli_query($connect2db,$sql);
	  $num=mysqli_num_rows($query);
	  if($num==1){
			   $row=mysqli_fetch_array($query);
			   $_SESSION['id']=$row['id'];
			   $_SESSION['fullname']=$row['fullname'];
			   $_SESSION['email']=$row['email'];
			   //echo "<script language='javascript'>".'alert("Successful!")'.$_SESSION['username'].'<-/script>';
			   //echo $_SESSION['username'];
			   	echo "<script language='javascript'>".'alert("You are logged in successfully")'.'</script>';
			   }
			else{
				echo "<script language='javascript'>".'alert("You have entered wrong username/password!")'.'</script>';
				 
				}
	  }
?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<link rel="stylesheet" type="text/css" href="style.css">
	<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css" rel="stylesheet"/>
	<title>Home</title>
</head>
<body>
	<div class="container">
		<form action="#" method="post">
			<img src="client.png" id="image" width="234px" height="234px"><br>
			<label id="team">Team Treasure</label><br>
			<input type="text" class="form-control name" placeholder="&#xf007; Username" id="name" name="username"><br>
			<input type="password" class="form-control name" name="password" id="password" placeholder="&#xf023; Password"><br>
			<input type="submit" name="submit" id="submit" value="Login"><br>
			<label id="forget">Forgot Username or Password?</label><br>
			<a href="signup_page.php">Create New Account</a>
<!-- target="_blank"    -->
		</form>
	</div>

</body>
</html>