function edituser(user,password,container){
	$("#userform #user").val(user)
	$("#userform #password").val(password)
	$("#userform #container").val(container)
}

function editdatabase(user,password,container){
	console.log(user)
	console.log(password)
	console.log(container)
	$("#databaseform #user").val(user)
	$("#databaseform #dbpassword").val(password)
	$("#databaseform #container").val(container)
}

function clearuser(name){
	$("#userform #user").val("")
	$("#userform #password").val("")
	$("#userform #container").val(name)
}

function editdomain(domain,www,ssl,container){
	$("#domainform #domain").val(domain)
	$("#domainform #certificate").val(ssl)
        if(www==1){
	        $("#domainform #www").bootstrapSwitch('state', 1);
	}else{
		$("#romainform #www").bootstrapSwitch('state', 0);
	}
        $("#domainform #container").val(container)
}

function cleardomain(container){
	$("#domainform #domain").val("")
	$("#domainform #certificate").val("")
	$("#domainform #www").bootstrapSwitch('state', 0);
	$("#domainform #container").val(container)
}

function cleardatabase(container){
        $("#databaseform #user").val("")
        $("#databaseform #dbpassword").val("")
        $("#databaseform #container").val(container)
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
