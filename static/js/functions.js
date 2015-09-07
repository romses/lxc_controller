function edituser(user,password,role){
	$("#userform #user").val(user)
	$("#userform #password").val(password)
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
