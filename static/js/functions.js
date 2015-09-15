function edituser(user,password,role){
	$("#userform #user").val(user)
	$("#userform #password").val(password)
}

function editdatabase(user,password){
	$("#databaseform #user").val(user)
	$("#databaseform #dbpassword").val(password)
}

function clearuser(){
	$("#userform #user").val("")
	$("#userform #password").val("")
}

function editdomain(domain,www,ssl){
	$("#domainform #domain").val(domain)
	$("#domainform #certificate").val(ssl)
        if(www==1){
	        $("#domainform #www").bootstrapSwitch('state', 1);
	}else{
		$("#romainform #www").bootstrapSwitch('state', 0);
	}
}

function cleardomain(){
	$("#domainform #domain").val("")
	$("#domainform #certificate").val("")
	$("#romainform #www").bootstrapSwitch('state', 0);
}

function cleardatabase(){
        $("#databaseform #user").val("")
        $("#databaseform #dbpassword").val("")
}


$(document).ready(function(){
	$("#userrandom").click(function(){
		$("#userform #password").val(randomPassword(8))
	})
	$("#dbuserrandom").click(function(){
		$("#databaseform #dbpassword").val(randomPassword(8))
	})
});

function randomPassword(length)
{
  chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
  pass = "";
  for(x=0;x<length;x++)
  {
    i = Math.floor(Math.random() * 62);
    pass += chars.charAt(i);
  }
  return pass;
}
