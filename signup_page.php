
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<link rel="stylesheet" type="text/css" href="style.css">
	<title>Sign Up</title>
</head>
<body>
	<div class="container-signup">
		<div class="signup-image">
			<img src="background.jpeg" id="s.image" width="820px" height="0px"><br>
			<!-- <i id="team">TEAM TREASURE</i> -->
		</div>
		<div id="signup-form">
			<form action="" method="post">
			<h2>Sign Up</h2>
			<label>Full Name</label><br>
			<input type="text" class="form-control name" name="fullname" required><br>
			<label id="em">Email</label><br>
			<input type="Email" class="form-control name" name="email" required><br>
			<label>Username</label><br>
			<input type="name" name="username" required><br>
			<label id="">Password?</label><br>
			<input type="password" name="password" id="s.password" required><br>
			<label>Repeat Password</label><br>
			<input type="password" name="repassword" id="repassword" required><br>
			<!-- <input type="checkbox" name="checkbox" id="check"><i id="check-writeup">I agree to the terms of User</i> <br>	 -->
			<input type="submit" name="signup" id="signup" value="Sign Up" onClick="valid()">
			<a href="index.php" id="signin">Sign in</a>

		</form>
		</div>
		
	</div>

</body>
</html>
<?php
include_once('dbcon.php');
 
if(isset($_POST['signup'])){
$fname= $_POST['fullname'];
$mail= $_POST['email'];
$usern= $_POST['username'];
$password= $_POST['password'];
		
$sql="INSERT INTO registration (fullname, email, password, username) VALUES ('$fname', '$mail', '$password', '$usern') ";
		$query=mysqli_query($connect2db,$sql) or die(mysqli_error($connect2db));
echo '<script language="javascript">'."alert('You have successfully registered a staff!')"."alert('Click here to view your signin page')"."</script>";

}
?>
<script type="text/javascript">
function valid(){
const password =document.getElementById("s.password");
const repassword = document.getElementById("repassword");

if(password.value != repassword.value)
{
alert("Password and Confirm Password Field do not match  !!");
document.getElementById(repassword).focus();
return false;
}
return true;
}

</script>