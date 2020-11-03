## Encountered Bugs
- [ ] disabled state of umc/widgets/DateBox is broken

## Instances where new design is not optimal
- [ ] hovered links in tooltips are unreadable
- [ ] login - umcLoginWarning has now bad contrast against background
- [ ] login - umcLoginWarnings has now bad contrast against form

## Discussions
- [ ] should default position of label change to top?
- [ ] discuss *:focus outline: none
  - [ ] a tag
- [ ] login - "This network connection is not encrypted. Click here for an HTTPS connection." is red but on hover it gets green. Should this be changed?


## Possible cleanups / enhancements
- [ ] compress umc.css
- [ ] could almost completely remove dijit.css (most of the stuff is just overridden)
- [ ] put login style into univention-management-console (currently lives in univention-web; there were errors when creating a Makefile in univention-management-console)
- [ ] NotificationSnackbar.js and dialog.js::contextNotify parameter changed; grep to change usages
	- [ ] fix docs for dialog.js::context{Notify,Warn} and NotificationSnackbar.js (the function parameter changed)

## Portal cleanups
- [ ] move stylings from portal to univention-web
	- [ ] "icons.styl"
	- [ ] "widgets.styl"
	- [ ] "Dialog.styl"
	- [ ] "render.styl"(?)
	- [ ] "menu.styl"
	- [ ] "notifications.styl"

## User Stories
- [ ] implement univention_ucs_ui_2 > Design: Typografie
  - mostly implemented. listing missing things
  - [ ] Discuss how the font is integrated (using google fonts api, having it in source code, ...)
  - [ ] correctly implement csp for font if using google fonts api
- [ ] implement univention_ucs_ui_2 > Design: Iconografie
  - [ ] Discussion/Decision how icons are used (as font, single files,.inline-svg, ..) at the moment we (mostyl) use a single svg with multiple icons. The disadvantage is the the icons can only have one size since it is not possible to scale a portion of the whole svg
  - [ ] Umsetzung (Icons austauschen, ggf Ergebnis des oberen Punkts umsetzen)
- [ ] implement univention_ucs_ui_2 > Komponenten: Header
  - [ ] implement tab design (can look at univention-portal)
  - [ ] implement search
  - [ ] implement notifications (can look at univention-portal; move design from there to univention-web)
  - [ ] implement menu (can look at univention-portal; move design from there to univention-web)
    - [ ] add the menu back to login
- [ ] implement univention_ucs_ui_2 > Komponenten: Buttons
  - [x] Primary Button
  - [x] Secondary Button
  - [x] Text button
  - [x] Icon Button
  - [ ] ToggleButton
  - [ ] DropDownButton
  - [ ] Check box-shadow on buttons
  - [ ] Check, decide and use the css classes for the different button types
- [ ] implement univention_ucs_ui_2 > Komponenten: EingabeFelder
  - [ ] TextBox/Select/TextArea
    - mostly implemented. listing missing things
    - [ ] when removing input from an required field the label gets immediately red but not the border of the input field (this should be synced in either direction)
    - [ ] Disabled/Error state: icons for dropdown etc have to be grey/red too
  - [x] CheckBox/Radio
  - [ ] Switch
    - [ ] Discussion: do we need a Switch widget?
      - [ ] implement if yes
  - [ ] MultiSelect/MultiObjectSelect
  - [ ] MultiInput (This may be its own User Story)
    - [ ] Discussion: Inline Edit and/or PopupDialog
    - [ ] JS/HTML for Table layout
    - [ ] CSS
  - [ ] Uploader (and Variants)
- [ ] implement univention_ucs_ui_2 > Komponenten: Tabellen
  - [ ] cleanup: fix memory aspect of creating CheckBox widgets in the Grid
- [ ] implement univention_ucs_ui_2 > Komponenten: Aufklapper
- [ ] implement univention_ucs_ui_2 > Komponenten: Overlays
  - [ ] CSS for the Dialog underlay
  - [ ] CSS for Dialogs
  - [ ] check Dialog usages for 'closable' and footerButtons (should use actionBarTemplate)
- [ ] implement univention_ucs_ui_2 > Komponenten: Banner / Tooltips
  - [x] tooltip
  - [ ] Banner (this is NotificationSnackbar which is used by umc.dialog.contextNotify)
- [ ] implement univention_ucs_ui_2 > Komponenten: Ladeanzeige
  - [ ] adjust Standby.js StandbyMixin etc
  - [ ] adjust ProgressBar widget
- [ ] implement univention_ucs_ui_2 > Komponenten: Baumstruktur
- [ ] implement univention_ucs_ui_2 > Komponenten: Kacheln
  - [ ] "Kachel ohne Bild" "Kachel mit Bild" (can be ignored for i think)
  - [ ] "Kachel für Benutzer mit Bild"
  - [ ] "InfoKachel" will be done in seperate App Center User story
- [ ] implement univention_ucs_ui_2 > Komponenten: Diverses
  - [ ] "Darstellungswechsler" (User module)
  - [ ] "Context Menü"
  - [ ] "Pagination für Seiten" can be ignored for now
  - [ ] "Pagination für Slider" will be done in seperate App Center user story
- [ ] UMC module changes
  - [ ] css for the layout (content, tabs, buttons, etc)
  - [ ] Discussion: Module icon before title (see univention_screendesign_05 > modul gruppen (14))
  - [ ] Breadcrumbs (see univention_screendesign_05 > modul gruppen: gruppe bearbeiten (15))
- [ ] AppCenter module changes (univention_screendesign_05 18, 19, 20, 21, 22, 23)

- [ ] adjust the login to the new design 
  - mostly implemented. listing missing things
  - [ ] hover/focus styling of input fields
  - [ ] login h1 is now h2 // instances where h1 is checked/accessed have to be changed
  - [ ] check LoginNotice
  - [ ] check - loading anim still consumes cpu if only on opacity 0 (?)
  - [ ] revise loading animation
  - [ ] check if the placeholder=" " and :placeholder-shown works in supported browsers (should still be usable in browsers that dont support it)
  - [ ] adopt login changes to the saml login
