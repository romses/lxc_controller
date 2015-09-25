$(document).ready(function(){
        $(".yesnoswitch").bootstrapSwitch();
        $('[data-toggle="tooltip"]').tooltip();
})

function start(name){
        uri="/container/start/" + name
        $.get(uri,function(){
                window.location.reload()
        });
}

function stop(name){
        uri="/container/stop/" + name
        $.get(uri,function(){
                window.location.reload()
        });
}

function del(name){
	BootstrapDialog.show({
            message: 'Delete container '+name+"?",
            buttons: [{
                label: 'Delete',
                cssClass: 'btn-danger',
		action: function(){
			window.location.href='/container/delete/'+name
		}
            }, {
                label: 'Cancel',
                cssClass: 'btn-primary',
                action: function(dialogItself){
                    dialogItself.close();
                }
            }]
	});
}

function confirm(msg,action){
	BootstrapDialog.show({
		message: msg,
		buttons: [{
			label: 'Delete',
			cssClass: 'btn-danger',
			action: action
		},{
			label: 'Cancel',
			cssClass: 'btn-primary',
			action: function(dialogItself){
				dialogItself.close();
			}
		}]
	});
}

function confirmbackup(msg,action){
	BootstrapDialog.show({
		message: msg,
		buttons: [{
			label: 'Backup',
			cssClass: 'btn-success',
			action: function(dialogItself){
				action();
				dialogItself.close();
                        }
		},{
			label: 'Cancel',
			cssClass: 'btn-primary',
			action: function(dialogItself){
				dialogItself.close();
			}
		}]
	});
}
