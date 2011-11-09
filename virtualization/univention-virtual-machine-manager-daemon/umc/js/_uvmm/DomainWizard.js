/*global console MyError dojo dojox dijit umc */

dojo.provide("umc.modules._uvmm.DomainWizard");

dojo.require("umc.widgets.Wizard");
dojo.require("umc.i18n");
dojo.require("umc.tools");
dojo.require("umc.store");
dojo.require("umc.widgets.TitlePane");
dojo.require("umc.modules._uvmm.types");
dojo.require("umc.modules._uvmm.DriveGrid");

dojo.declare("umc.modules._uvmm.DomainWizard", [ umc.widgets.Wizard, umc.i18n.Mixin ], {
	
	i18nClass: 'umc.modules.uvmm',

	_profile: null,

	_driveStore: null,
	_driveGrid: null,
	_driveContainer: null,

	constructor: function() {
		var types = umc.modules._uvmm.types;

		// grid for the drives
		this._driveStore = new umc.store.Memory({
			idProperty: 'source'
		});
		this._driveGrid = new umc.modules._uvmm.DriveGrid({
			moduleStore: this._driveStore
		});

		// wrap grid in a titlepane
		var titlePane = new umc.widgets.TitlePane({
			title: this._('Drives')
		});
		titlePane.addChild(this._driveGrid);
		
		// and the titlepane into a container
		this._driveContainer  = new umc.widgets.ContainerWidget({
			scrollable: true,
			region: 'center'
		});
		this._driveContainer.addChild(titlePane);

		// mixin the page structure
		dojo.mixin(this, {
			pages: [{
				name: 'profile',
				headerText: this._('Create a virtual instance'),
				helpText: this._('By selecting a profile for the virtual instance most of the settings will be set to default values. In the following steps some of these values might be modified. After the creation of the virtual instance all parameters, extended settings und attached drives can be adjusted. It should be ensured that the profile is for the correct architecture as this option can not be changed afterwards.'),
				widgets: [{
					name: 'nodeURI',
					type: 'ComboBox',
					label: this._('Physical server'),
					dynamicValues: types.getNodes
				}, {
					name: 'profile',
					type: 'ComboBox',
					label: this._('Profile'),
					depends: 'nodeURI',
					dynamicValues: types.getProfiles
				}]
			}, {
				name: 'general',
				headerText: '...',
				helpText: this._('The following settings were read from the selected profile and can be modified now.'),
				widgets: [{
					name: 'nodeURI',
					type: 'HiddenInput'
				}, {
					name: '$profile$',
					type: 'HiddenInput'
				}, {
					name: 'domain_type',
					type: 'HiddenInput'
				}, {
					name: 'name',
					type: 'TextBox',
					label: this._('Name')
				}, {
					name: 'description',
					type: 'TextBox',
					label: this._('Description')
				}, {
					name: 'maxMem',
					type: 'TextBox',
					label: this._('Memory (default unit MB)')
				}, {
					name: 'vcpus',
					type: 'ComboBox',
					label: this._('Number of CPUs'),
					depends: 'nodeURI',
					dynamicValues: types.getCPUs
				}, {
					name: 'vnc',
					type: 'CheckBox',
					label: this._('Enable direct access')
				}]
			}, {
				name: 'drives',
				headerText: this._('Add drive'),
				helpText: this._('To finalize the creation of the virtual instance, please add one or more drives by clicking on "Add drive".')
			}]
		});
	},

	buildRendering: function() {
		this.inherited(arguments);

		// add the drive grid to the last page
		this._pages.drives.addChild(this._driveContainer);

		// connect to the onShow method of the drives page to adjust the size of the grid
		this.connect(this._pages.drives, 'onShow', function() {
			this._driveGrid.resize();
		});
	},

	next: function(pageName) {
		var nextName = this.inherited(arguments);

		if (pageName == 'profile') {
			// query the profile settings
			this.standby(true);
			var profileDN = this.getWidget('profile').get('value'); 
			umc.tools.umcpCommand('uvmm/profile/get', {
				profileDN: profileDN
			}).then(dojo.hitch(this, function(data) {
				// we got the profile...
				this._profile = data.result;
				this._profile.profileDN = profileDN;

				// pre-set the form fields
				this.getWidget('general', 'nodeURI').set('value', this.getWidget('profile', 'nodeURI').get('value'));
				this.getWidget('$profile$').set('value', profileDN);
				this.getWidget('domain_type').set('value', this._profile.virttech.split('-')[0]);
				this.getWidget('name').set('value', this._profile.name_prefix || '');
				this.getWidget('maxMem').set('value', this._profile.ram || '');
				this.getWidget('vcpus').set('value', this._profile.cpus);
				this.getWidget('vnc').set('value', this._profile.vnc);

				// update page header
				this._pages.general.set('headerText', this._('Create a virtual instance (profile: %s)', this._profile.name));

				this.standby(false);
			}), dojo.hitch(this, function() {
				// fallback... switch off the standby animation
				this.standby(false);
			}));
		}
		else if (pageName == 'general') {
			// update the domain info for the drive grid
			this._driveGrid.domain = this.getValues();
		}

		return nextName;
	},

	getValues: function() {
		var values = this._pages.general._form.gatherFormValues();
		values.nodeURI = this.getWidget('nodeURI').get('value');
		values.vnc_remote = true;
		values.disks = this._driveStore.data;
		values.interfaces = [{
			paravirtual: this._profile.pvinterface,
			source: this._profile['interface']
		}];
		return values;
	}
});





