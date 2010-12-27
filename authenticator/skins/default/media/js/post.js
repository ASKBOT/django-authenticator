﻿/*
Scripts for cnprog.com
Project Name: Lanai
All Rights Resevred 2008. CNPROG.COM
*/
var lanai =
{
    /**
     * Finds any <pre><code></code></pre> tags which aren't registered for
     * pretty printing, adds the appropriate class name and invokes prettify.
     */
    highlightSyntax: function(){
        var styled = false;
        $("pre code").parent().each(function(){
            if (!$(this).hasClass('prettyprint')){
                $(this).addClass('prettyprint');
                styled = true;
            }
        });

        if (styled){
            prettyPrint();
        }
    }
};

var getUniqueWords = function(value){
    return $.unique($.trim(value).split(/\s+/));
};

function appendLoader(element) {
    element.append('<img class="ajax-loader" ' +
        'src="' + mediaUrl("media/images/indicator.gif") + '" title="' +
        $.i18n._('loading...') +
        '" alt="' +
        $.i18n._('loading...') +
    '" />');
}

function removeLoader() {
    $("img.ajax-loader").remove();
}

function setSubmitButtonDisabled(form, isDisabled) { 
    form.find("input[type='submit']").attr("disabled", isDisabled ? "true" : "");    
}

function enableSubmitButton(form) {
    setSubmitButtonDisabled(form, false);
}

function disableSubmitButton(form) {
    setSubmitButtonDisabled(form, true);
}

function setupFormValidation(form, validationRules, validationMessages, onSubmitCallback) {
    enableSubmitButton(form);
    form.validate({
        debug: true,
        rules: (validationRules ? validationRules : {}),
        messages: (validationMessages ? validationMessages : {}),
        errorElement: "span",
        errorClass: "form-error",
        errorPlacement: function(error, element) {
            var span = element.next().find("span.form-error");
            if (span.length === 0) {
                span = element.parent().find("span.form-error");
                if (span.length === 0){
                    //for resizable textarea
                    var element_id = element.attr('id');
                    span = $("label[for='" + element_id + "']");
                }
            }
            span.replaceWith(error);
        },
        submitHandler: function(form_dom) {
            disableSubmitButton($(form_dom));
            
            if (onSubmitCallback){
                onSubmitCallback();
            } 
            else{
                form_dom.submit();
            }
        }
    });
}

var validateTagLength = function(value){
    var tags = getUniqueWords(value);
    var are_tags_ok = true;
    $.each(tags, function(index, value){
        if (value.length > askbot['settings']['maxTagLength']){
            are_tags_ok = false;
        }
    });
    return are_tags_ok;
};
var validateTagCount = function(value){
    var tags = getUniqueWords(value);
    return (tags.length <= askbot['settings']['maxTagsPerPost']);
};

$.validator.addMethod('limit_tag_count', validateTagCount);
$.validator.addMethod('limit_tag_length', validateTagLength);

var CPValidator = function(){
    return {
        getQuestionFormRules : function(){
            return {
                tags: {
                    required: true,
                    maxlength: 105,
                    limit_tag_count: true,
                    limit_tag_length: true
                },  
                text: {
                    required: true,
                    minlength: 10
                },
                title: {
                    required: true,
                    minlength: 10
                }
            };
        },
        getQuestionFormMessages: function(){
            return {
                tags: {
                    required: " " + $.i18n._('tags cannot be empty'),
                    maxlength: askbot['messages']['tagLimits'],
                    limit_tag_count: askbot['messages']['maxTagsPerPost'],
                    limit_tag_length: askbot['messages']['maxTagLength']
                },
                text: {
                    required: " " + $.i18n._('content cannot be empty'),
                    minlength: $.i18n._('content minchars').replace('{0}', 10)
                },
                title: {
                    required: " " + $.i18n._('please enter title'),
                    minlength: $.i18n._('title minchars').replace('{0}', 10)
                }
            };
        }
    };
}();


var Vote = function(){
    // All actions are related to a question
    var questionId;
    //question slug to build redirect urls
    var questionSlug;
    // The object we operate on actually. It can be a question or an answer.
    var postId;
    var questionAuthorId;
    var currentUserId;
    var answerContainerIdPrefix = 'answer-container-';
    var voteContainerId = 'vote-buttons';
    var imgIdPrefixAccept = 'answer-img-accept-';
    var imgClassPrefixFavorite = 'question-img-favorite';
    var imgIdPrefixQuestionVoteup = 'question-img-upvote-';
    var imgIdPrefixQuestionVotedown = 'question-img-downvote-';
    var imgIdPrefixAnswerVoteup = 'answer-img-upvote-';
    var imgIdPrefixAnswerVotedown = 'answer-img-downvote-';
    var divIdFavorite = 'favorite-number';
    var commentLinkIdPrefix = 'comment-';
    var voteNumberClass = "vote-number";
    var offensiveIdPrefixQuestionFlag = 'question-offensive-flag-';
    var offensiveIdPrefixAnswerFlag = 'answer-offensive-flag-';
    var offensiveClassFlag = 'offensive-flag';
    var questionControlsId = 'question-controls';
    var removeQuestionLinkIdPrefix = 'question-delete-link-';
    var removeAnswerLinkIdPrefix = 'answer-delete-link-';
    var questionSubscribeUpdates = 'question-subscribe-updates';
    
    var acceptAnonymousMessage = $.i18n._('insufficient privilege');
    var acceptOwnAnswerMessage = $.i18n._('cannot pick own answer as best');

    var pleaseLogin = " <a href='" + askbot['urls']['user_signin']
                    + "?next=" + askbot['urls']['question_url_template']
                    + "'>"
                    + $.i18n._('please login') + "</a>";

    var favoriteAnonymousMessage = $.i18n._('anonymous users cannot select favorite questions') + pleaseLogin;
    var voteAnonymousMessage = $.i18n._('anonymous users cannot vote') + pleaseLogin;
    //there were a couple of more messages...
    var offensiveConfirmation = $.i18n._('please confirm offensive');
    var offensiveAnonymousMessage = $.i18n._('anonymous users cannot flag offensive posts') + pleaseLogin;
    var removeConfirmation = $.i18n._('confirm delete');
    var removeAnonymousMessage = $.i18n._('anonymous users cannot delete/undelete') + pleaseLogin;
    var recoveredMessage = $.i18n._('post recovered');
    var deletedMessage = $.i18n._('post deleted');
    
    var VoteType = {
        acceptAnswer : 0,
        questionUpVote : 1,
        questionDownVote : 2,
        favorite : 4,
        answerUpVote: 5,
        answerDownVote:6,
        offensiveQuestion : 7,
        offensiveAnswer:8,
        removeQuestion: 9,
        removeAnswer:10,
        questionSubscribeUpdates:11,
        questionUnsubscribeUpdates:12
    };

    var getFavoriteButton = function(){
        var favoriteButton = 'div.'+ voteContainerId +' img[class='+ imgClassPrefixFavorite +']';
        return $(favoriteButton);
    };
    var getFavoriteNumber = function(){
        var favoriteNumber = '#'+ divIdFavorite ;
        return $(favoriteNumber);
    };
    var getQuestionVoteUpButton = function(){
        var questionVoteUpButton = 'div.'+ voteContainerId +' img[id^='+ imgIdPrefixQuestionVoteup +']';
        return $(questionVoteUpButton);
    };
    var getQuestionVoteDownButton = function(){
        var questionVoteDownButton = 'div.'+ voteContainerId +' img[id^='+ imgIdPrefixQuestionVotedown +']';
        return $(questionVoteDownButton);
    };
    var getAnswerVoteUpButtons = function(){
        var answerVoteUpButton = 'div.'+ voteContainerId +' img[id^='+ imgIdPrefixAnswerVoteup +']';
        return $(answerVoteUpButton);
    };
    var getAnswerVoteDownButtons = function(){
        var answerVoteDownButton = 'div.'+ voteContainerId +' img[id^='+ imgIdPrefixAnswerVotedown +']';
        return $(answerVoteDownButton);
    };
    var getAnswerVoteUpButton = function(id){
        var answerVoteUpButton = 'div.'+ voteContainerId +' img[id='+ imgIdPrefixAnswerVoteup + id + ']';
        return $(answerVoteUpButton);
    };
    var getAnswerVoteDownButton = function(id){
        var answerVoteDownButton = 'div.'+ voteContainerId +' img[id='+ imgIdPrefixAnswerVotedown + id + ']';
        return $(answerVoteDownButton);
    };
    
    var getOffensiveQuestionFlag = function(){
        var offensiveQuestionFlag = '#question-table span[class='+ offensiveClassFlag +']';
        return $(offensiveQuestionFlag);
    };
    
    var getOffensiveAnswerFlags = function(){
        var offensiveQuestionFlag = 'div.answer span[class='+ offensiveClassFlag +']';
        return $(offensiveQuestionFlag);
    };
    
    var getremoveQuestionLink = function(){
        var removeQuestionLink = 'div#question-controls a[id^='+ removeQuestionLinkIdPrefix +']';
        return $(removeQuestionLink);
    };

    var getquestionSubscribeUpdatesCheckbox = function(){
        return $('#' + questionSubscribeUpdates);
    };
    
    var getremoveAnswersLinks = function(){
        var removeAnswerLinks = 'div.answer-controls a[id^='+ removeAnswerLinkIdPrefix +']';
        return $(removeAnswerLinks);
    };
   
    var setVoteImage = function(voteType, undo, object){
        var flag = undo ? "" : "-on";
        var arrow = (voteType == VoteType.questionUpVote || voteType == VoteType.answerUpVote) ? "up" : "down";
        object.attr("src", mediaUrl("media/images/vote-arrow-"+ arrow + flag +".png"));
        
        // if undo voting, then undo the pair of arrows.
        if(undo){
            if(voteType == VoteType.questionUpVote || voteType == VoteType.questionDownVote){
                $(getQuestionVoteUpButton()).attr("src", mediaUrl("media/images/vote-arrow-up.png"));
                $(getQuestionVoteDownButton()).attr("src", mediaUrl("media/images/vote-arrow-down.png"));
            }
            else{
                $(getAnswerVoteUpButton(postId)).attr("src", mediaUrl("media/images/vote-arrow-up.png"));
                $(getAnswerVoteDownButton(postId)).attr("src", mediaUrl("media/images/vote-arrow-down.png"));
            }
        }
    };
    
    var setVoteNumber = function(object, number){
        var voteNumber = object.parent('div.'+ voteContainerId).find('div.'+ voteNumberClass);
        $(voteNumber).text(number);
    };
    
    var bindEvents = function(){
        // accept answers
        if(questionAuthorId == currentUserId){
            var acceptedButtons = 'div.'+ voteContainerId +' img[id^='+ imgIdPrefixAccept +']';
            $(acceptedButtons).unbind('click').click(function(event){
               Vote.accept($(event.target));
            });
        }
        // set favorite question
        var favoriteButton = getFavoriteButton();
        favoriteButton.unbind('click').click(function(event){
           Vote.favorite($(event.target));
        });
    
        // question vote up
        var questionVoteUpButton = getQuestionVoteUpButton();
        questionVoteUpButton.unbind('click').click(function(event){
           Vote.vote($(event.target), VoteType.questionUpVote);
        });
    
        var questionVoteDownButton = getQuestionVoteDownButton();
        questionVoteDownButton.unbind('click').click(function(event){
           Vote.vote($(event.target), VoteType.questionDownVote);
        });
    
        var answerVoteUpButton = getAnswerVoteUpButtons();
        answerVoteUpButton.unbind('click').click(function(event){
           Vote.vote($(event.target), VoteType.answerUpVote);
        });
        
        var answerVoteDownButton = getAnswerVoteDownButtons();
        answerVoteDownButton.unbind('click').click(function(event){
           Vote.vote($(event.target), VoteType.answerDownVote);
        });
    
        getOffensiveQuestionFlag().unbind('click').click(function(event){
           Vote.offensive(this, VoteType.offensiveQuestion);
        });
    
        getOffensiveAnswerFlags().unbind('click').click(function(event){
           Vote.offensive(this, VoteType.offensiveAnswer);
        });
    
        getremoveQuestionLink().unbind('click').click(function(event){
            Vote.remove(this, VoteType.removeQuestion);
        });

        getquestionSubscribeUpdatesCheckbox().unbind('click').click(function(event){
            if (this.checked){
                Vote.vote($(event.target), VoteType.questionSubscribeUpdates);
            }
            else {
                Vote.vote($(event.target), VoteType.questionUnsubscribeUpdates);
            }
        });
    
        getremoveAnswersLinks().unbind('click').click(function(event){
            Vote.remove(this, VoteType.removeAnswer);
        });
    };
    
    var submit = function(object, voteType, callback) {
        //this function submits votes
        $.ajax({
            type: "POST",
            cache: false,
            dataType: "json",
            url: askbot['urls']['vote_url_template'].replace('{{QuestionID}}', questionId),
            data: { "type": voteType, "postId": postId },
            error: handleFail,
            success: function(data){callback(object, voteType, data);}
            });
    };
    
    var handleFail = function(xhr, msg){
        alert("Callback invoke error: " + msg);
    };

    // callback function for Accept Answer action
    var callback_accept = function(object, voteType, data){
        if(data.allowed == "0" && data.success == "0"){
            showMessage(object, acceptAnonymousMessage);
        }
        else if(data.allowed == "-1"){
            showMessage(object, acceptOwnAnswerMessage);
        }
        else if(data.status == "1"){
            object.attr("src", mediaUrl("media/images/vote-accepted.png"));
            $("#"+answerContainerIdPrefix+postId).removeClass("accepted-answer");
            $("#"+commentLinkIdPrefix+postId).removeClass("comment-link-accepted");
        }
        else if(data.success == "1"){
            var acceptedButtons = 'div.'+ voteContainerId +' img[id^='+ imgIdPrefixAccept +']';
            $(acceptedButtons).attr("src", mediaUrl("media/images/vote-accepted.png"));
            var answers = ("div[id^="+answerContainerIdPrefix +"]");
            $(answers).removeClass("accepted-answer");
            var commentLinks = ("div[id^="+answerContainerIdPrefix +"] div[id^="+ commentLinkIdPrefix +"]");
            $(commentLinks).removeClass("comment-link-accepted");
            
            object.attr("src", mediaUrl("media/images/vote-accepted-on.png"));
            $("#"+answerContainerIdPrefix+postId).addClass("accepted-answer");
            $("#"+commentLinkIdPrefix+postId).addClass("comment-link-accepted");
        }
        else{
            showMessage(object, data.message);
        }
    };

    var callback_favorite = function(object, voteType, data){
        if(data.allowed == "0" && data.success == "0"){
            showMessage(
                object, 
                favoriteAnonymousMessage.replace(
                        '{{QuestionID}}', 
                        questionId).replace(
                        '{{questionSlug}}',
                        '' 
                    )
            );
        }
        else if(data.status == "1"){
            object.attr("src", mediaUrl("media/images/vote-favorite-off.png"));
            var fav = getFavoriteNumber();
            fav.removeClass("my-favorite-number");
            if(data.count === 0){
                data.count = '';
            }
            fav.text(data.count);
        }
        else if(data.success == "1"){
            object.attr("src", mediaUrl("media/images/vote-favorite-on.png"));
            var fav = getFavoriteNumber();
            fav.text(data.count);
            fav.addClass("my-favorite-number");
        }
        else{
            showMessage(object, data.message);
        }
    };
        
    var callback_vote = function(object, voteType, data){
        if (data.success == '0'){
            showMessage(object, data.message);
            return;
        }
        else {
            if (data.status == '1'){
                setVoteImage(voteType, true, object);
            }
            else {
                setVoteImage(voteType, false, object);
            }
            setVoteNumber(object, data.count);
            if (data.message && data.message.length > 0){
                showMessage(object, data.message);
            }
            return;
        }
        //may need to take a look at this again
        if (data.status == "1"){
            setVoteImage(voteType, true, object);
            setVoteNumber(object, data.count);
        }     
        else if (data.success == "1"){
            setVoteImage(voteType, false, object);
            setVoteNumber(object, data.count);
            if (data.message.length > 0){
                showMessage(object, data.message);
            }
        }
    };
        
    var callback_offensive = function(object, voteType, data){
        //todo: transfer proper translations of these from i18n.js
        //to django.po files
        //_('anonymous users cannot flag offensive posts') + pleaseLogin;
        if (data.success == "1"){
            $(object).children('span[class=darkred]').text("("+ data.count +")");
        }
        else {
            object = $(object);
            showMessage(object, data.message)
        }
    };
        
    var callback_remove = function(object, voteType, data){
        if (data.success == "1"){
            if (removeActionType == 'delete'){
                postNode.addClass('deleted');
                postRemoveLink.innerHTML = $.i18n._('undelete');
                showMessage(object, deletedMessage);
            }
            else if (removeActionType == 'undelete') {
                postNode.removeClass('deleted');
                postRemoveLink.innerHTML = $.i18n._('delete');
                showMessage(object, recoveredMessage);
            }
        }
        else {
            showMessage(object, data.message)
        }
    };
        
    return {
        init : function(qId, qSlug, questionAuthor, userId){
            questionId = qId;
            questionSlug = qSlug;
            questionAuthorId = questionAuthor;
            currentUserId = userId;
            bindEvents();
        },
        
        //accept answer
        accept: function(object){
            postId = object.attr("id").substring(imgIdPrefixAccept.length);
            submit(object, VoteType.acceptAnswer, callback_accept);
        },
        //mark question as favorite
        favorite: function(object){
            if (!currentUserId || currentUserId.toUpperCase() == "NONE"){
                showMessage(
                    object, 
                    favoriteAnonymousMessage.replace(
                            "{{QuestionID}}",
                            questionId
                        ).replace(
                            '{{questionSlug}}',
                            questionSlug
                        )
                );
                return false;
            }
            submit(object, VoteType.favorite, callback_favorite);
        },
            
        vote: function(object, voteType){
            if (!currentUserId || currentUserId.toUpperCase() == "NONE"){
                showMessage(
                    $(object),
                    voteAnonymousMessage.replace(
                            "{{QuestionID}}",
                            questionId
                        ).replace(
                            '{{questionSlug}}',
                            questionSlug
                        )
                );
                return false;
            }
            // up and downvote processor
            if (voteType == VoteType.answerUpVote){
                postId = object.attr("id").substring(imgIdPrefixAnswerVoteup.length);
            }
            else if (voteType == VoteType.answerDownVote){
                postId = object.attr("id").substring(imgIdPrefixAnswerVotedown.length);
            }
            
            submit(object, voteType, callback_vote);
        },
        //flag offensive
        offensive: function(object, voteType){
            if (!currentUserId || currentUserId.toUpperCase() == "NONE"){
                showMessage(
                    $(object),
                    offensiveAnonymousMessage.replace(
                            "{{QuestionID}}",
                            questionId
                        ).replace(
                            '{{questionSlug}}',
                            questionSlug
                        )
                );
                return false;   
            }
            if (confirm(offensiveConfirmation)){
                postId = object.id.substr(object.id.lastIndexOf('-') + 1);
                submit(object, voteType, callback_offensive);
            }
        },
        //delete question or answer (comments are deleted separately)
        remove: function(object, voteType){
            if (!currentUserId || currentUserId.toUpperCase() == "NONE"){
                showMessage(
                    $(object),
                    removeAnonymousMessage.replace(
                            '{{QuestionID}}',
                            questionId
                        ).replace(
                            '{{questionSlug}}',
                            questionSlug
                        )
                    );
                return false;   
            }
            bits = object.id.split('-');
            postId = bits.pop();/* this seems to be used within submit! */
            postType = bits.shift();

            var do_proceed = false; 
            if (postType == 'answer'){
                postNode = $('#answer-container-' + postId);
            }
            else if (postType == 'question'){
                postNode = $('#question-table');
            }
            postRemoveLink = object;
            if (postNode.hasClass('deleted')){
                removeActionType = 'undelete';
                do_proceed = true;
            }
            else {
                removeActionType = 'delete';
                do_proceed = confirm(removeConfirmation);
            }
            if (do_proceed) {
                submit($(object), voteType, callback_remove);
            }
        }
    };
} ();

var questionRetagger = function(){

    var oldTagsHTML = '';
    var tagInput = null;
    var tagsDiv = null;
    var retagLink = null;

    var restoreEventHandlers = function(){
        $(document).unbind('click');
    };

    var cancelRetag = function(){
        tagInput.unautocomplete();//removes dropdown if open
        tagsDiv.html(oldTagsHTML);
        tagsDiv.removeClass('post-retag');
        tagsDiv.addClass('post-tags');
        restoreEventHandlers();
        initRetagger();
    };

    var render_tag = function(tag_name){
        //copy-paste from live search!!!
        var url = askbot['urls']['questions'] + 
                    '?tags=' + encodeURI(tag_name);
        var tag_title = $.i18n._(
                            "see questions tagged '{tag}'"
                        ).replace(
                            '{tag}',
                            tag_name
                        );
        return '<a ' +
                    'href="' + url + '" ' + 
                    'title="' + tag_title + '" rel="tag"' +
                '>' + tag_name + '</a>';
    };

    var drawNewTags = function(new_tags){
        new_tags = new_tags.split(/\s+/);
        var tags_html = ''
        $.each(new_tags, function(index, name){
            if (index === 0){
                tags_html = render_tag(name);
            }
            else {
                tags_html += ' ' + render_tag(name);
            }
        });
        tagsDiv.html(tags_html);
    };

    var doRetag = function(){
        $.ajax({
            type: "POST",
            url: retagUrl,
            dataType: "json",
            data: { tags: getUniqueWords(tagInput.val()).join(' ') },
            success: function(json) {
                if (json['success'] === true){
                    new_tags = getUniqueWords(tagInput.val());
                    oldTagsHtml = '';
                    cancelRetag();
                    drawNewTags(new_tags.join(' '));
                }
                else {
                    cancelRetag();
                    showMessage(tagsDiv, json['message']);
                }
            },
            error: function(xhr, textStatus, errorThrown) {
                showMessage(tagsDiv, 'sorry, somethin is not right here');
                cancelRetag();
            }
        });
        return false;
    }

    var setupInputEventHandlers = function(input){
        input.keydown(function(e){
            if ((e.which && e.which == 27) || (e.keyCode && e.keyCode == 27)){
                cancelRetag();
            }
        });
        $(document).unbind('click').click(cancelRetag, false);
        input.click(function(){return false});
    };

    var createRetagForm = function(old_tags_string){
        var div = $('<form method="post"></form>');
        tagInput = $('<input id="retag_tags" type="text" autocomplete="off" name="tags" size="30"/>');
        //var tagLabel = $('<label for="retag_tags" class="error"></label>');
        tagInput.val(old_tags_string);
        //populate input
        //todo: make autocomplete work
        tagInput.autocomplete(tags_autocomplete, {
                minChars: 1,
                matchContains: true,
                selectFirst: false,
                max: 20,
                multiple: true,
                multipleSeparator: " ",
                formatItem: function(row, i, max) {
                    return row.n + " ("+ row.c +")";
                },
                formatResult: function(row, i, max){
                    return row.n;
                }
        });

        div.append(tagInput);
        //div.append(tagLabel);
        setupInputEventHandlers(tagInput);

        //button = $('<input type="submit" />');
        //button.val($.i18n._('save tags'));
        //div.append(button);
        //setupButtonEventHandlers(button);
        div.validate({//copy-paste from utils.js
            rules: {
                tags: {
                    required: true,
                    maxlength: askbot['settings']['maxTagsPerPost'] * askbot['settings']['maxTagLength'],
                    limit_tag_count: true,
                    limit_tag_length: true
                }
            },
            messages: {
                tags: {
                    required: $.i18n._('tags cannot be empty'),
                    maxlength: askbot['messages']['tagLimits'],
                    limit_tag_count: askbot['messages']['maxTagsPerPost'],
                    limit_tag_length: askbot['messages']['maxTagLength']
                }
            },
            submitHandler: doRetag,
            errorClass: "retag-error"
        });

        return div;
    };

    var getTagsAsString = function(tags_div){
        var links = tags_div.find('a');
        var tags_str = '';
        links.each(function(index, element){
            if (index === 0){
                tags_str = $(element).html();
            }
            else {
                tags_str += ' ' + $(element).html();
            }
        });
        return tags_str;
    };

    var noopHandler = function(){
        tagInput.focus();
        return false;
    };

    var deactivateRetagLink = function(){
        retagLink.unbind('click').click(noopHandler);
        retagLink.unbind('keypress').keypress(noopHandler);
    };

    var startRetag = function(){
        tagsDiv = $('#question-tags');
        oldTagsHTML = tagsDiv.html();//save to restore on cancel
        var old_tags_string = getTagsAsString(tagsDiv);
        var retag_form = createRetagForm(old_tags_string);
        tagsDiv.html('');
        tagsDiv.append(retag_form);
        tagsDiv.removeClass('post-tags');
        tagsDiv.addClass('post-retag');
        tagInput.focus();
        deactivateRetagLink();
        return false;
    };

    var setupClickAndEnterHandler = function(element, callback){
        element.unbind('click').click(callback);
        element.unbind('keypress').keypress(function(e){
            if ((e.which && e.which == 13) || (e.keyCode && e.keyCode == 13)){
                callback();
            }
        });
    }

    var initRetagger = function(){
        setupClickAndEnterHandler(retagLink, startRetag);
    };

    return {
        init: function(){
            retagLink = $('#retag');
            initRetagger();
        }
    };
}();

inherits = function(childCtor, parentCtor) {
  /** @constructor taken from google closure */
    function tempCtor() {};
    tempCtor.prototype = parentCtor.prototype;
    childCtor.superClass_ = parentCtor.prototype;
    childCtor.prototype = new tempCtor();
    childCtor.prototype.constructor = childCtor;
};

/* wrapper around jQuery object */
var WrappedElement = function(){
    this._element = null;
};
WrappedElement.prototype.setElement = function(element){
    this._element = element;
};
WrappedElement.prototype.createDom = function(){
    this._element = $('<div></div>');
};
WrappedElement.prototype.getElement = function(){
    if (this._element === null){
        this.createDom();
    }
    return this._element;
};
WrappedElement.prototype.dispose = function(){
    this._element.remove();
};

var SimpleControl = function(){
    WrappedElement.call(this);
    this._handler = null;
};
inherits(SimpleControl, WrappedElement);

SimpleControl.prototype.setHandler = function(handler){
    this._handler = handler;
};

var EditLink = function(){
    SimpleControl.call(this)
};
inherits(EditLink, SimpleControl);

EditLink.prototype.createDom = function(){
    var element = $('<a></a>');
    element.addClass('edit');
    this.decorate(element);
};

EditLink.prototype.decorate = function(element){
    this._element = element;
    this._element.attr('title', $.i18n._('click to edit this comment'));
    this._element.html($.i18n._('edit'));
    setupButtonEventHandlers(this._element, this._handler);
};

var DeleteIcon = function(title){
    SimpleControl.call(this);
    this._title = title;
};
inherits(DeleteIcon, SimpleControl);

DeleteIcon.prototype.decorate = function(element){
    this._element = element;
    var img = mediaUrl("media/images/close-small.png");
    var imgHover = mediaUrl("media/images/close-small-hover.png");
    this._element.attr('class', 'delete-icon');
    this._element.attr('src', img);
    this._element.attr('title', this._title);
    setupButtonEventHandlers(this._element, this._handler);
    this._element.mouseover(function(e){
        $(this).attr('src', imgHover);
    });
    this._element.mouseout(function(e){
        $(this).attr('src', img);
    });
};

DeleteIcon.prototype.createDom = function(){
    this.decorate($('<img />'));
};


//constructor for the form
var EditCommentForm = function(){
    WrappedElement.call(this);
    this._comment = null;
    this._comment_widget = null;
    this._element = null;
    this._text = '';
    this._id = 'edit-comment-form';
};
inherits(EditCommentForm, WrappedElement);

EditCommentForm.prototype.getElement = function(){
    EditCommentForm.superClass_.getElement.call(this);
    this._textarea.val(this._text);
    return this._element;
};

EditCommentForm.prototype.attachTo = function(comment, mode){
    this._comment = comment;
    this._type = mode;
    this._comment_widget = comment.getContainerWidget();
    this._text = comment.getText();
    comment.getElement().after(this.getElement());
    comment.getElement().hide();
    this._comment_widget.hideButton();
    if (this._type == 'add'){
        this._submit_btn.html($.i18n._('add comment'));
    }
    else {
        this._submit_btn.html($.i18n._('save comment'));
    }
    this.getElement().show();
    this.focus();
    putCursorAtEnd(this._textarea);
};

EditCommentForm.prototype.getCounterUpdater = function(){
    //returns event handler
    var counter = this._text_counter;
    var handler = function(){
        var textarea = $(this);
        var length = textarea.val() ? textarea.val().length : 0;
        var length1 = maxCommentLength - 100;
        if (length1 < 0){
            length1 = Math.round(0.7*maxCommentLength);
        }
        var length2 = maxCommentLength - 30;
        if (length2 < 0){
            length2 = Math.round(0.9*maxCommentLength);
        }
        
        var color = 'maroon';
        if (length === 0){
            var feedback = $.i18n._('title minchars').replace('{0}', 10);
        }
        else if (length < 10){
            var feedback = $.i18n._('enter more characters').replace('{0}', 10 - length);
        }
        else {
            color = length > length2 ? "#f00" : length > length1 ? "#f60" : "#999";
            var feedback = $.i18n._('can write') + ' ' + 
                    (maxCommentLength - length) + ' ' +
                    $.i18n._('characters');
        }
        counter.html(feedback).css('color', color);
    };
    return handler;
};

EditCommentForm.prototype.canCancel = function(){
    if (this._element === null){
        return true;
    }
    var ctext = $.trim(this._textarea.val());
    if ($.trim(ctext) == $.trim(this._text)){
        return true;
    }
    else if (this.confirmAbandon()){
        return true;
    }
    this.focus();
    return false;
};

EditCommentForm.prototype.getCancelHandler = function(){
    var form = this;
    return function(){
        if (form.canCancel()){
            form.detach();
        } 
        return false;
    };
};

EditCommentForm.prototype.detach = function(){
    if (this._comment === null){
        return;
    }
    this._comment.getContainerWidget().showButton();
    if (this._comment.isBlank()){
        this._comment.dispose();
    }
    else {
        this._comment.getElement().show();
    }
    this.reset();
    this._element = this._element.detach();
};

EditCommentForm.prototype.createDom = function(){
    this._element = $('<form></form>');
    this._element.attr('class', 'post-comments');

    var div = $('<div></div>');
    this._textarea = $('<textarea></textarea>');
    this._textarea.attr('id', this._id);


    this._element.append(div);
    div.append(this._textarea);
    this._text_counter = $('<span></span>').attr('class', 'counter');
    div.append(this._text_counter);
    this._submit_btn = $('<button class="submit small"></button>');
    div.append(this._submit_btn);
    this._cancel_btn = $('<button class="submit small"></button>');
    this._cancel_btn.html($.i18n._('cancel'));
    div.append(this._cancel_btn);

    setupButtonEventHandlers(this._submit_btn, this.getSaveHandler());
    setupButtonEventHandlers(this._cancel_btn, this.getCancelHandler());

    var update_counter = this.getCounterUpdater();
    var escape_handler = makeKeyHandler(27, this.getCancelHandler());
    var save_handler = makeKeyHandler(13, this.getSaveHandler());
    this._textarea.attr('name', 'comment')
            .attr('cols', 60)
            .attr('rows', 5)
            .attr('maxlength', maxCommentLength)
            .blur(update_counter)
            .focus(update_counter)
            .keyup(update_counter)
            .keyup(escape_handler)
            .keydown(save_handler);
    this._textarea.val(this._text);
};

EditCommentForm.prototype.enableButtons = function(){
    this._submit_btn.attr('disabled', '');
    this._cancel_btn.attr('disabled', '');
};

EditCommentForm.prototype.disableButtons = function(){
    this._submit_btn.attr('disabled', 'disabled');
    this._cancel_btn.attr('disabled', 'disabled');
};

EditCommentForm.prototype.reset = function(){
    this._comment = null;
    this._text = '';
    this._textarea.val('');
    this.enableButtons();
};

EditCommentForm.prototype.confirmAbandon = function(){
    this.focus(true);
    this._textarea.addClass('highlight');
    var answer = confirm($.i18n._('confirm abandon comment'));
    this._textarea.removeClass('highlight');
    return answer;
};

EditCommentForm.prototype.focus = function(hard){
    this._textarea.focus();
    if (hard === true){
        $(this._textarea).scrollTop();
    }
};

EditCommentForm.prototype.getSaveHandler = function(){

    var me = this;
    return function(){
        var text = me._textarea.val();
        if (text.length <= 10){
            me.focus();
            return false;
        }

        var post_data = {
            comment: text
        };

        if (me._type == 'edit'){
            post_data['comment_id'] = me._comment.getId();
            post_url = askbot['urls']['editComment'];
        }
        else {
            post_data['post_type'] = me._comment.getParentType();
            post_data['post_id'] = me._comment.getParentId();
            post_url = askbot['urls']['postComments'];
        }

        me.disableButtons();

        $.ajax({
            type: "POST",
            url: post_url,
            dataType: "json",
            data: post_data,
            success: function(json) {
                if (me._type == 'add'){
                    me._comment.dispose();
                    me._comment.getContainerWidget().reRenderComments(json);
                }
                else {
                    me._comment.setContent(json);
                    me._comment.getElement().show();
                }
                me.detach();
            },
            error: function(xhr, textStatus, errorThrown) {
                me._comment.getElement().show();
                showMessage(me._comment.getElement(), xhr.responseText, 'after');
                me.detach();
                me.enableButtons();
            }
        });
        return false;
    };
};

//a single instance to reuse
var editCommentForm = new EditCommentForm();

var Comment = function(widget, data){
    WrappedElement.call(this);
    this._container_widget = widget;
    this._data = data || {};
    this._blank = true;//set to false by setContent
    this._element = null;
    this._delete_prompt = $.i18n._('delete this comment');
    if (data && data['is_deletable']){
        this._deletable = data['is_deletable'];
    }
    else {
        this._deletable = false;
    }
    if (data && data['is_editable']){
        this._editable = data['is_deletable'];
    }
    else {
        this._editable = false;
    }
};
inherits(Comment, WrappedElement);

Comment.prototype.decorate = function(element){
    this._element = $(element);
    var parent_type = this._element.parent().parent().attr('id').split('-')[2];
    var comment_id = this._element.attr('id').replace('comment-','');
    this._data = {id: comment_id};
    var delete_img = this._element.find('img.delete-icon');
    if (delete_img.length > 0){
        this._deletable = true;
        this._delete_icon = new DeleteIcon(this.deletePrompt);
        this._delete_icon.setHandler(this.getDeleteHandler());
        this._delete_icon.decorate(delete_img);
    }
    var edit_link = this._element.find('a.edit');
    if (edit_link.length > 0){
        this._editable = true;
        this._edit_link = new EditLink();
        this._edit_link.setHandler(this.getEditHandler());
        this._edit_link.decorate(edit_link);
    }

    this._blank = false;
};

Comment.prototype.isBlank = function(){
    return this._blank;
};

Comment.prototype.getId = function(){
    return this._data['id'];
};

Comment.prototype.hasContent = function(){
    return ('id' in this._data);
    //shortcut for 'user_url' 'html' 'user_display_name' 'comment_age'
};

Comment.prototype.hasText = function(){
    return ('text' in this._data);
}

Comment.prototype.getContainerWidget = function(){
    return this._container_widget;
};

Comment.prototype.getParentType = function(){
    return this._container_widget.getPostType();
};

Comment.prototype.getParentId = function(){
    return this._container_widget.getPostId();
};

Comment.prototype.setContent = function(data){
    this._data = data || this._data;
    this._element.html('');
    this._element.attr('class', 'comment');
    this._element.attr('id', 'comment-' + this._data['id']);

    this._element.append(this._data['html']);
    this._element.append(' - ');

    this._user_link = $('<a></a>').attr('class', 'author');
    this._user_link.attr('href', this._data['user_url']);
    this._user_link.html(this._data['user_display_name']);
    this._element.append(this._user_link);

    this._element.append(' (');
    this._comment_age = $('<span class="age"></span>');
    this._comment_age.html(this._data['comment_age']);
    this._element.append(this._comment_age);
    this._element.append(')');

    if (this._editable){
        this._edit_link = new EditLink();
        this._edit_link.setHandler(this.getEditHandler())
        this._element.append(this._edit_link.getElement());
    }

    if (this._deletable){
        this._delete_icon = new DeleteIcon(this._delete_prompt);
        this._delete_icon.setHandler(this.getDeleteHandler());
        this._element.append(this._delete_icon.getElement());
    }
    this._blank = false;
};

Comment.prototype.dispose = function(){
    if (this._user_link){
        this._user_link.remove();
    }
    if (this._comment_age){
        this._comment_age.remove();
    }
    if (this._delete_icon){
        this._delete_icon.dispose();
    }
    if (this._edit_link){
        this._edit_link.dispose();
    }
    this._data = null;
    Comment.superClass_.dispose.call(this);
};

Comment.prototype.getElement = function(){
    Comment.superClass_.getElement.call(this);
    if (this.isBlank() && this.hasContent()){
        this.setContent();
        if (enableMathJax === true){
            MathJax.Hub.Queue(['Typeset', MathJax.Hub]);
        }
    }
    return this._element;
};

Comment.prototype.loadText = function(on_load_handler){
    var me = this;
    $.ajax({
        type: "GET",
        url: askbot['urls']['getComment'],
        data: {id: this._data['id']},
        success: function(json){
            me._data['text'] = json['text'];
            on_load_handler()
        },
        error: function(xhr, textStatus, exception) {
            showMessage(me.getElement(), xhr.responseText, 'after');
        }
    });
};

Comment.prototype.getText = function(){
    if (!this.isBlank()){
        if ('text' in this._data){
            return this._data['text'];
        }
    }
    return '';
}

Comment.prototype.getEditHandler = function(){
    var comment = this;
    return function(){
        if (editCommentForm.canCancel()){
            editCommentForm.detach();
            if (comment.hasText()){
                editCommentForm.attachTo(comment, 'edit');
            }
            else {
                comment.loadText(
                    function(){
                        editCommentForm.attachTo(comment, 'edit');
                    }
                );
            }
        }
    };
};

Comment.prototype.getDeleteHandler = function(){
    var comment = this;
    var del_icon = this._delete_icon;
    return function(){
        if (confirm($.i18n._('confirm delete comment'))){
            comment.getElement().hide();
            $.ajax({
                type: 'POST',
                url: askbot['urls']['deleteComment'], 
                data: { comment_id: comment.getId() }, 
                success: function(json, textStatus, xhr) {
                    comment.dispose();
                }, 
                error: function(xhr, textStatus, exception) {
                    comment.getElement().show()
                    showMessage(del_icon.getElement(), xhr.responseText);
                },
                dataType: "json"
            });
        }
    };
};

var PostCommentsWidget = function(){
    WrappedElement.call(this);
    this._denied = false;
};
inherits(PostCommentsWidget, WrappedElement);

PostCommentsWidget.prototype.decorate = function(element){
    var element = $(element);
    this._element = element;

    var widget_id = element.attr('id');
    var id_bits = widget_id.split('-');
    this._post_id = id_bits[3];
    this._post_type = id_bits[2];
    this._is_truncated = askbot['data'][widget_id]['truncated'];
    this._user_can_post = askbot['data'][widget_id]['can_post'];

    //see if user can comment here
    var controls = element.find('.controls');
    this._activate_button = controls.find('.button');

    if (this._user_can_post == false){
        setupButtonEventHandlers(
            this._activate_button,
            this.getReadOnlyLoadHandler()
        );
    }
    else {
        setupButtonEventHandlers(
            this._activate_button,
            this.getActivateHandler()
        );
    }

    this._cbox = element.find('.content');
    var comments = new Array();
    var me = this;
    this._cbox.children().each(function(index, element){
        var comment = new Comment(me);
        comments.push(comment)
        comment.decorate(element);
    });
    this._comments = comments;
};

PostCommentsWidget.prototype.getPostType = function(){
    return this._post_type;
};

PostCommentsWidget.prototype.getPostId = function(){
    return this._post_id;
};

PostCommentsWidget.prototype.hideButton = function(){
    this._activate_button.hide();
};

PostCommentsWidget.prototype.showButton = function(){
    if (this._is_truncated === false){
        this._activate_button.html(askbot['messages']['addComment']);
    }
    this._activate_button.show();
}

PostCommentsWidget.prototype.startNewComment = function(){
    var comment = new Comment(this);
    this._cbox.append(comment.getElement());
    editCommentForm.attachTo(comment, 'add');
};

PostCommentsWidget.prototype.needToReload = function(){
    return this._is_truncated;
};

PostCommentsWidget.prototype.getActivateHandler = function(){
    var me = this;
    return function() {
        if (editCommentForm.canCancel()){
            editCommentForm.detach();
            if (me.needToReload()){
                me.reloadAllComments(function(json){
                    me.reRenderComments(json);
                    me.startNewComment();
                });
            }
            else {
                me.startNewComment();
            }
        }
    };
};

PostCommentsWidget.prototype.getReadOnlyLoadHandler = function(){
    var me = this;
    return function(){
        me.reloadAllComments(function(json){
            me.reRenderComments(json);
            me._activate_button.remove();
        });
    };
};


PostCommentsWidget.prototype.reloadAllComments = function(callback){
    var post_data = {post_id: this._post_id, post_type: this._post_type};
    var me = this;
    $.ajax({
        type: "GET",
        url: askbot['urls']['postComments'],
        data: post_data,
        success: function(json){
            callback(json);
            me._is_truncated = false;
        },
        dataType: "json"
    });
};

PostCommentsWidget.prototype.reRenderComments = function(json){
    $.each(this._comments, function(i, item){
        item.dispose();
    });
    this._comments = new Array();
    var me = this;
    $.each(json, function(i, item){
        var comment = new Comment(me, item);
        me._cbox.append(comment.getElement());
        me._comments.push(comment);
    });
};


var socialSharing = function(){

    var SERVICE_DATA = {
        //url - template for the sharing service url, params are for the popup
        twitter: {
            url: "http://twitter.com/share?url={URL}&ref=twitbtn&text={TEXT}",
            params: "width=820,height=526,toolbar=1,status=1,resizable=1,scrollbars=1"
        },
        facebook: {
            url: "http://www.facebook.com/sharer.php?u={URL}&ref=fbshare&t={TEXT}",
            params: "width=630,height=436,toolbar=1,status=1,resizable=1,scrollbars=1"
        }
    };
    var URL = "";
    var TEXT = "";

    var share_page = function(service_name){
        if (SERVICE_DATA[service_name]){
            var url = SERVICE_DATA[service_name]['url'];
            url = url.replace('{URL}', URL);
            url = url.replace('{TEXT}', TEXT);
            var params = SERVICE_DATA[service_name]['params'];
            if(!window.open(url, "sharing", params)){
                window.location.href=share_url;
            }
        }
    }

    return {
        init: function(page_url, text_to_share){
            URL = window.location.href;
            TEXT = escape($('div.headNormal > a').html());
            var fb = $('a.fb-share')
            var tw = $('a.twitter-share');
            copyAltToTitle(fb);
            copyAltToTitle(tw);
            setupButtonEventHandlers(fb, function(){share_page("facebook")});
            setupButtonEventHandlers(tw, function(){share_page("twitter")});
        }
    }
}(); 

$(document).ready(function() {
    $('[id^="comments-for-"]').each(function(index, element){
        var comments = new PostCommentsWidget();
        comments.decorate(element);
    });
    questionRetagger.init();
    socialSharing.init();
});


/*
Prettify
http://www.apache.org/licenses/LICENSE-2.0
*/
var PR_SHOULD_USE_CONTINUATION = true; var PR_TAB_WIDTH = 8; var PR_normalizedHtml; var PR; var prettyPrintOne; var prettyPrint; function _pr_isIE6() { var isIE6 = navigator && navigator.userAgent && /\bMSIE 6\./.test(navigator.userAgent); _pr_isIE6 = function() { return isIE6; }; return isIE6; } (function() { function wordSet(words) { words = words.split(/ /g); var set = {}; for (var i = words.length; --i >= 0; ) { var w = words[i]; if (w) { set[w] = null; } } return set; } var FLOW_CONTROL_KEYWORDS = "break continue do else for if return while "; var C_KEYWORDS = FLOW_CONTROL_KEYWORDS + "auto case char const default " + "double enum extern float goto int long register short signed sizeof " + "static struct switch typedef union unsigned void volatile "; var COMMON_KEYWORDS = C_KEYWORDS + "catch class delete false import " + "new operator private protected public this throw true try "; var CPP_KEYWORDS = COMMON_KEYWORDS + "alignof align_union asm axiom bool " + "concept concept_map const_cast constexpr decltype " + "dynamic_cast explicit export friend inline late_check " + "mutable namespace nullptr reinterpret_cast static_assert static_cast " + "template typeid typename typeof using virtual wchar_t where "; var JAVA_KEYWORDS = COMMON_KEYWORDS + "boolean byte extends final finally implements import instanceof null " + "native package strictfp super synchronized throws transient "; var CSHARP_KEYWORDS = JAVA_KEYWORDS + "as base by checked decimal delegate descending event " + "fixed foreach from group implicit in interface internal into is lock " + "object out override orderby params readonly ref sbyte sealed " + "stackalloc string select uint ulong unchecked unsafe ushort var "; var JSCRIPT_KEYWORDS = COMMON_KEYWORDS + "debugger eval export function get null set undefined var with " + "Infinity NaN "; var PERL_KEYWORDS = "caller delete die do dump elsif eval exit foreach for " + "goto if import last local my next no our print package redo require " + "sub undef unless until use wantarray while BEGIN END "; var PYTHON_KEYWORDS = FLOW_CONTROL_KEYWORDS + "and as assert class def del " + "elif except exec finally from global import in is lambda " + "nonlocal not or pass print raise try with yield " + "False True None "; var RUBY_KEYWORDS = FLOW_CONTROL_KEYWORDS + "alias and begin case class def" + " defined elsif end ensure false in module next nil not or redo rescue " + "retry self super then true undef unless until when yield BEGIN END "; var SH_KEYWORDS = FLOW_CONTROL_KEYWORDS + "case done elif esac eval fi " + "function in local set then until "; var ALL_KEYWORDS = (CPP_KEYWORDS + CSHARP_KEYWORDS + JSCRIPT_KEYWORDS + PERL_KEYWORDS + PYTHON_KEYWORDS + RUBY_KEYWORDS + SH_KEYWORDS); var PR_STRING = 'str'; var PR_KEYWORD = 'kwd'; var PR_COMMENT = 'com'; var PR_TYPE = 'typ'; var PR_LITERAL = 'lit'; var PR_PUNCTUATION = 'pun'; var PR_PLAIN = 'pln'; var PR_TAG = 'tag'; var PR_DECLARATION = 'dec'; var PR_SOURCE = 'src'; var PR_ATTRIB_NAME = 'atn'; var PR_ATTRIB_VALUE = 'atv'; var PR_NOCODE = 'nocode'; function isWordChar(ch) { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'); } function spliceArrayInto(inserted, container, containerPosition, countReplaced) { inserted.unshift(containerPosition, countReplaced || 0); try { container.splice.apply(container, inserted); } finally { inserted.splice(0, 2); } } var REGEXP_PRECEDER_PATTERN = function() { var preceders = ["!", "!=", "!==", "#", "%", "%=", "&", "&&", "&&=", "&=", "(", "*", "*=", "+=", ",", "-=", "->", "/", "/=", ":", "::", ";", "<", "<<", "<<=", "<=", "=", "==", "===", ">", ">=", ">>", ">>=", ">>>", ">>>=", "?", "@", "[", "^", "^=", "^^", "^^=", "{", "|", "|=", "||", "||=", "~", "break", "case", "continue", "delete", "do", "else", "finally", "instanceof", "return", "throw", "try", "typeof"]; var pattern = '(?:' + '(?:(?:^|[^0-9.])\\.{1,3})|' + '(?:(?:^|[^\\+])\\+)|' + '(?:(?:^|[^\\-])-)'; for (var i = 0; i < preceders.length; ++i) { var preceder = preceders[i]; if (isWordChar(preceder.charAt(0))) { pattern += '|\\b' + preceder; } else { pattern += '|' + preceder.replace(/([^=<>:&])/g, '\\$1'); } } pattern += '|^)\\s*$'; return new RegExp(pattern); } (); var pr_amp = /&/g; var pr_lt = /</g; var pr_gt = />/g; var pr_quot = /\"/g; function attribToHtml(str) { return str.replace(pr_amp, '&amp;').replace(pr_lt, '&lt;').replace(pr_gt, '&gt;').replace(pr_quot, '&quot;'); } function textToHtml(str) { return str.replace(pr_amp, '&amp;').replace(pr_lt, '&lt;').replace(pr_gt, '&gt;'); } var pr_ltEnt = /&lt;/g; var pr_gtEnt = /&gt;/g; var pr_aposEnt = /&apos;/g; var pr_quotEnt = /&quot;/g; var pr_ampEnt = /&amp;/g; var pr_nbspEnt = /&nbsp;/g; function htmlToText(html) { var pos = html.indexOf('&'); if (pos < 0) { return html; } for (--pos; (pos = html.indexOf('&#', pos + 1)) >= 0; ) { var end = html.indexOf(';', pos); if (end >= 0) { var num = html.substring(pos + 3, end); var radix = 10; if (num && num.charAt(0) === 'x') { num = num.substring(1); radix = 16; } var codePoint = parseInt(num, radix); if (!isNaN(codePoint)) { html = (html.substring(0, pos) + String.fromCharCode(codePoint) + html.substring(end + 1)); } } } return html.replace(pr_ltEnt, '<').replace(pr_gtEnt, '>').replace(pr_aposEnt, "'").replace(pr_quotEnt, '"').replace(pr_ampEnt, '&').replace(pr_nbspEnt, ' '); } function isRawContent(node) { return 'XMP' === node.tagName; } function normalizedHtml(node, out) { switch (node.nodeType) { case 1: var name = node.tagName.toLowerCase(); out.push('<', name); for (var i = 0; i < node.attributes.length; ++i) { var attr = node.attributes[i]; if (!attr.specified) { continue; } out.push(' '); normalizedHtml(attr, out); } out.push('>'); for (var child = node.firstChild; child; child = child.nextSibling) { normalizedHtml(child, out); } if (node.firstChild || !/^(?:br|link|img)$/.test(name)) { out.push('<\/', name, '>'); } break; case 2: out.push(node.name.toLowerCase(), '="', attribToHtml(node.value), '"'); break; case 3: case 4: out.push(textToHtml(node.nodeValue)); break; } } var PR_innerHtmlWorks = null; function getInnerHtml(node) { if (null === PR_innerHtmlWorks) { var testNode = document.createElement('PRE'); testNode.appendChild(document.createTextNode('<!DOCTYPE foo PUBLIC "foo bar">\n<foo />')); PR_innerHtmlWorks = !/</.test(testNode.innerHTML); } if (PR_innerHtmlWorks) { var content = node.innerHTML; if (isRawContent(node)) { content = textToHtml(content); } return content; } var out = []; for (var child = node.firstChild; child; child = child.nextSibling) { normalizedHtml(child, out); } return out.join(''); } function makeTabExpander(tabWidth) { var SPACES = '                '; var charInLine = 0; return function(plainText) { var out = null; var pos = 0; for (var i = 0, n = plainText.length; i < n; ++i) { var ch = plainText.charAt(i); switch (ch) { case '\t': if (!out) { out = []; } out.push(plainText.substring(pos, i)); var nSpaces = tabWidth - (charInLine % tabWidth); charInLine += nSpaces; for (; nSpaces >= 0; nSpaces -= SPACES.length) { out.push(SPACES.substring(0, nSpaces)); } pos = i + 1; break; case '\n': charInLine = 0; break; default: ++charInLine; } } if (!out) { return plainText; } out.push(plainText.substring(pos)); return out.join(''); }; } var pr_chunkPattern = /(?:[^<]+|<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<\/?[a-zA-Z][^>]*>|<)/g; var pr_commentPrefix = /^<!--/; var pr_cdataPrefix = /^<\[CDATA\[/; var pr_brPrefix = /^<br\b/i; var pr_tagNameRe = /^<(\/?)([a-zA-Z]+)/; function extractTags(s) { var matches = s.match(pr_chunkPattern); var sourceBuf = []; var sourceBufLen = 0; var extractedTags = []; if (matches) { for (var i = 0, n = matches.length; i < n; ++i) { var match = matches[i]; if (match.length > 1 && match.charAt(0) === '<') { if (pr_commentPrefix.test(match)) { continue; } if (pr_cdataPrefix.test(match)) { sourceBuf.push(match.substring(9, match.length - 3)); sourceBufLen += match.length - 12; } else if (pr_brPrefix.test(match)) { sourceBuf.push('\n'); ++sourceBufLen; } else { if (match.indexOf(PR_NOCODE) >= 0 && isNoCodeTag(match)) { var name = match.match(pr_tagNameRe)[2]; var depth = 1; end_tag_loop: for (var j = i + 1; j < n; ++j) { var name2 = matches[j].match(pr_tagNameRe); if (name2 && name2[2] === name) { if (name2[1] === '/') { if (--depth === 0) { break end_tag_loop; } } else { ++depth; } } } if (j < n) { extractedTags.push(sourceBufLen, matches.slice(i, j + 1).join('')); i = j; } else { extractedTags.push(sourceBufLen, match); } } else { extractedTags.push(sourceBufLen, match); } } } else { var literalText = htmlToText(match); sourceBuf.push(literalText); sourceBufLen += literalText.length; } } } return { source: sourceBuf.join(''), tags: extractedTags }; } function isNoCodeTag(tag) { return !!tag.replace(/\s(\w+)\s*=\s*(?:\"([^\"]*)\"|'([^\']*)'|(\S+))/g, ' $1="$2$3$4"').match(/[cC][lL][aA][sS][sS]=\"[^\"]*\bnocode\b/); } function createSimpleLexer(shortcutStylePatterns, fallthroughStylePatterns) { var shortcuts = {}; (function() { var allPatterns = shortcutStylePatterns.concat(fallthroughStylePatterns); for (var i = allPatterns.length; --i >= 0; ) { var patternParts = allPatterns[i]; var shortcutChars = patternParts[3]; if (shortcutChars) { for (var c = shortcutChars.length; --c >= 0; ) { shortcuts[shortcutChars.charAt(c)] = patternParts; } } } })(); var nPatterns = fallthroughStylePatterns.length; var notWs = /\S/; return function(sourceCode, opt_basePos) { opt_basePos = opt_basePos || 0; var decorations = [opt_basePos, PR_PLAIN]; var lastToken = ''; var pos = 0; var tail = sourceCode; while (tail.length) { var style; var token = null; var match; var patternParts = shortcuts[tail.charAt(0)]; if (patternParts) { match = tail.match(patternParts[1]); token = match[0]; style = patternParts[0]; } else { for (var i = 0; i < nPatterns; ++i) { patternParts = fallthroughStylePatterns[i]; var contextPattern = patternParts[2]; if (contextPattern && !contextPattern.test(lastToken)) { continue; } match = tail.match(patternParts[1]); if (match) { token = match[0]; style = patternParts[0]; break; } } if (!token) { style = PR_PLAIN; token = tail.substring(0, 1); } } decorations.push(opt_basePos + pos, style); pos += token.length; tail = tail.substring(token.length); if (style !== PR_COMMENT && notWs.test(token)) { lastToken = token; } } return decorations; }; } var PR_MARKUP_LEXER = createSimpleLexer([], [[PR_PLAIN, /^[^<]+/, null], [PR_DECLARATION, /^<!\w[^>]*(?:>|$)/, null], [PR_COMMENT, /^<!--[\s\S]*?(?:-->|$)/, null], [PR_SOURCE, /^<\?[\s\S]*?(?:\?>|$)/, null], [PR_SOURCE, /^<%[\s\S]*?(?:%>|$)/, null], [PR_SOURCE, /^<(script|style|xmp)\b[^>]*>[\s\S]*?<\/\1\b[^>]*>/i, null], [PR_TAG, /^<\/?\w[^<>]*>/, null]]); var PR_SOURCE_CHUNK_PARTS = /^(<[^>]*>)([\s\S]*)(<\/[^>]*>)$/; function tokenizeMarkup(source) { var decorations = PR_MARKUP_LEXER(source); for (var i = 0; i < decorations.length; i += 2) { if (decorations[i + 1] === PR_SOURCE) { var start, end; start = decorations[i]; end = i + 2 < decorations.length ? decorations[i + 2] : source.length; var sourceChunk = source.substring(start, end); var match = sourceChunk.match(PR_SOURCE_CHUNK_PARTS); if (match) { decorations.splice(i, 2, start, PR_TAG, start + match[1].length, PR_SOURCE, start + match[1].length + (match[2] || '').length, PR_TAG); } } } return decorations; } var PR_TAG_LEXER = createSimpleLexer([[PR_ATTRIB_VALUE, /^\'[^\']*(?:\'|$)/, null, "'"], [PR_ATTRIB_VALUE, /^\"[^\"]*(?:\"|$)/, null, '"'], [PR_PUNCTUATION, /^[<>\/=]+/, null, '<>/=']], [[PR_TAG, /^[\w:\-]+/, /^</], [PR_ATTRIB_VALUE, /^[\w\-]+/, /^=/], [PR_ATTRIB_NAME, /^[\w:\-]+/, null], [PR_PLAIN, /^\s+/, null, ' \t\r\n']]); function splitTagAttributes(source, decorations) { for (var i = 0; i < decorations.length; i += 2) { var style = decorations[i + 1]; if (style === PR_TAG) { var start, end; start = decorations[i]; end = i + 2 < decorations.length ? decorations[i + 2] : source.length; var chunk = source.substring(start, end); var subDecorations = PR_TAG_LEXER(chunk, start); spliceArrayInto(subDecorations, decorations, i, 2); i += subDecorations.length - 2; } } return decorations; } function sourceDecorator(options) { var shortcutStylePatterns = [], fallthroughStylePatterns = []; if (options.tripleQuotedStrings) { shortcutStylePatterns.push([PR_STRING, /^(?:\'\'\'(?:[^\'\\]|\\[\s\S]|\'{1,2}(?=[^\']))*(?:\'\'\'|$)|\"\"\"(?:[^\"\\]|\\[\s\S]|\"{1,2}(?=[^\"]))*(?:\"\"\"|$)|\'(?:[^\\\']|\\[\s\S])*(?:\'|$)|\"(?:[^\\\"]|\\[\s\S])*(?:\"|$))/, null, '\'"']); } else if (options.multiLineStrings) { shortcutStylePatterns.push([PR_STRING, /^(?:\'(?:[^\\\']|\\[\s\S])*(?:\'|$)|\"(?:[^\\\"]|\\[\s\S])*(?:\"|$)|\`(?:[^\\\`]|\\[\s\S])*(?:\`|$))/, null, '\'"`']); } else { shortcutStylePatterns.push([PR_STRING, /^(?:\'(?:[^\\\'\r\n]|\\.)*(?:\'|$)|\"(?:[^\\\"\r\n]|\\.)*(?:\"|$))/, null, '"\'']); } fallthroughStylePatterns.push([PR_PLAIN, /^(?:[^\'\"\`\/\#]+)/, null, ' \r\n']); if (options.hashComments) { shortcutStylePatterns.push([PR_COMMENT, /^#[^\r\n]*/, null, '#']); } if (options.cStyleComments) { fallthroughStylePatterns.push([PR_COMMENT, /^\/\/[^\r\n]*/, null]); fallthroughStylePatterns.push([PR_COMMENT, /^\/\*[\s\S]*?(?:\*\/|$)/, null]); } if (options.regexLiterals) { var REGEX_LITERAL = ('^/(?=[^/*])' + '(?:[^/\\x5B\\x5C]' + '|\\x5C[\\s\\S]' + '|\\x5B(?:[^\\x5C\\x5D]|\\x5C[\\s\\S])*(?:\\x5D|$))+' + '(?:/|$)'); fallthroughStylePatterns.push([PR_STRING, new RegExp(REGEX_LITERAL), REGEXP_PRECEDER_PATTERN]); } var keywords = wordSet(options.keywords); options = null; var splitStringAndCommentTokens = createSimpleLexer(shortcutStylePatterns, fallthroughStylePatterns); var styleLiteralIdentifierPuncRecognizer = createSimpleLexer([], [[PR_PLAIN, /^\s+/, null, ' \r\n'], [PR_PLAIN, /^[a-z_$@][a-z_$@0-9]*/i, null], [PR_LITERAL, /^0x[a-f0-9]+[a-z]/i, null], [PR_LITERAL, /^(?:\d(?:_\d+)*\d*(?:\.\d*)?|\.\d+)(?:e[+\-]?\d+)?[a-z]*/i, null, '123456789'], [PR_PUNCTUATION, /^[^\s\w\.$@]+/, null]]); function splitNonStringNonCommentTokens(source, decorations) { for (var i = 0; i < decorations.length; i += 2) { var style = decorations[i + 1]; if (style === PR_PLAIN) { var start, end, chunk, subDecs; start = decorations[i]; end = i + 2 < decorations.length ? decorations[i + 2] : source.length; chunk = source.substring(start, end); subDecs = styleLiteralIdentifierPuncRecognizer(chunk, start); for (var j = 0, m = subDecs.length; j < m; j += 2) { var subStyle = subDecs[j + 1]; if (subStyle === PR_PLAIN) { var subStart = subDecs[j]; var subEnd = j + 2 < m ? subDecs[j + 2] : chunk.length; var token = source.substring(subStart, subEnd); if (token === '.') { subDecs[j + 1] = PR_PUNCTUATION; } else if (token in keywords) { subDecs[j + 1] = PR_KEYWORD; } else if (/^@?[A-Z][A-Z$]*[a-z][A-Za-z$]*$/.test(token)) { subDecs[j + 1] = token.charAt(0) === '@' ? PR_LITERAL : PR_TYPE; } } } spliceArrayInto(subDecs, decorations, i, 2); i += subDecs.length - 2; } } return decorations; } return function(sourceCode) { var decorations = splitStringAndCommentTokens(sourceCode); decorations = splitNonStringNonCommentTokens(sourceCode, decorations); return decorations; }; } var decorateSource = sourceDecorator({ keywords: ALL_KEYWORDS, hashComments: true, cStyleComments: true, multiLineStrings: true, regexLiterals: true }); function splitSourceNodes(source, decorations) { for (var i = 0; i < decorations.length; i += 2) { var style = decorations[i + 1]; if (style === PR_SOURCE) { var start, end; start = decorations[i]; end = i + 2 < decorations.length ? decorations[i + 2] : source.length; var subDecorations = decorateSource(source.substring(start, end)); for (var j = 0, m = subDecorations.length; j < m; j += 2) { subDecorations[j] += start; } spliceArrayInto(subDecorations, decorations, i, 2); i += subDecorations.length - 2; } } return decorations; } function splitSourceAttributes(source, decorations) { var nextValueIsSource = false; for (var i = 0; i < decorations.length; i += 2) { var style = decorations[i + 1]; var start, end; if (style === PR_ATTRIB_NAME) { start = decorations[i]; end = i + 2 < decorations.length ? decorations[i + 2] : source.length; nextValueIsSource = /^on|^style$/i.test(source.substring(start, end)); } else if (style === PR_ATTRIB_VALUE) { if (nextValueIsSource) { start = decorations[i]; end = i + 2 < decorations.length ? decorations[i + 2] : source.length; var attribValue = source.substring(start, end); var attribLen = attribValue.length; var quoted = (attribLen >= 2 && /^[\"\']/.test(attribValue) && attribValue.charAt(0) === attribValue.charAt(attribLen - 1)); var attribSource; var attribSourceStart; var attribSourceEnd; if (quoted) { attribSourceStart = start + 1; attribSourceEnd = end - 1; attribSource = attribValue; } else { attribSourceStart = start + 1; attribSourceEnd = end - 1; attribSource = attribValue.substring(1, attribValue.length - 1); } var attribSourceDecorations = decorateSource(attribSource); for (var j = 0, m = attribSourceDecorations.length; j < m; j += 2) { attribSourceDecorations[j] += attribSourceStart; } if (quoted) { attribSourceDecorations.push(attribSourceEnd, PR_ATTRIB_VALUE); spliceArrayInto(attribSourceDecorations, decorations, i + 2, 0); } else { spliceArrayInto(attribSourceDecorations, decorations, i, 2); } } nextValueIsSource = false; } } return decorations; } function decorateMarkup(sourceCode) { var decorations = tokenizeMarkup(sourceCode); decorations = splitTagAttributes(sourceCode, decorations); decorations = splitSourceNodes(sourceCode, decorations); decorations = splitSourceAttributes(sourceCode, decorations); return decorations; } function recombineTagsAndDecorations(sourceText, extractedTags, decorations) { var html = []; var outputIdx = 0; var openDecoration = null; var currentDecoration = null; var tagPos = 0; var decPos = 0; var tabExpander = makeTabExpander(PR_TAB_WIDTH); var adjacentSpaceRe = /([\r\n ]) /g; var startOrSpaceRe = /(^| ) /gm; var newlineRe = /\r\n?|\n/g; var trailingSpaceRe = /[ \r\n]$/; var lastWasSpace = true; function emitTextUpTo(sourceIdx) { if (sourceIdx > outputIdx) { if (openDecoration && openDecoration !== currentDecoration) { html.push('</span>'); openDecoration = null; } if (!openDecoration && currentDecoration) { openDecoration = currentDecoration; html.push('<span class="', openDecoration, '">'); } var htmlChunk = textToHtml(tabExpander(sourceText.substring(outputIdx, sourceIdx))).replace(lastWasSpace ? startOrSpaceRe : adjacentSpaceRe, '$1&nbsp;'); lastWasSpace = trailingSpaceRe.test(htmlChunk); html.push(htmlChunk.replace(newlineRe, '<br />')); outputIdx = sourceIdx; } } while (true) { var outputTag; if (tagPos < extractedTags.length) { if (decPos < decorations.length) { outputTag = extractedTags[tagPos] <= decorations[decPos]; } else { outputTag = true; } } else { outputTag = false; } if (outputTag) { emitTextUpTo(extractedTags[tagPos]); if (openDecoration) { html.push('</span>'); openDecoration = null; } html.push(extractedTags[tagPos + 1]); tagPos += 2; } else if (decPos < decorations.length) { emitTextUpTo(decorations[decPos]); currentDecoration = decorations[decPos + 1]; decPos += 2; } else { break; } } emitTextUpTo(sourceText.length); if (openDecoration) { html.push('</span>'); } return html.join(''); } var langHandlerRegistry = {}; function registerLangHandler(handler, fileExtensions) { for (var i = fileExtensions.length; --i >= 0; ) { var ext = fileExtensions[i]; if (!langHandlerRegistry.hasOwnProperty(ext)) { langHandlerRegistry[ext] = handler; } else if ('console' in window) { console.log('cannot override language handler %s', ext); } } } registerLangHandler(decorateSource, ['default-code']); registerLangHandler(decorateMarkup, ['default-markup', 'html', 'htm', 'xhtml', 'xml', 'xsl']); registerLangHandler(sourceDecorator({ keywords: CPP_KEYWORDS, hashComments: true, cStyleComments: true }), ['c', 'cc', 'cpp', 'cs', 'cxx', 'cyc']); registerLangHandler(sourceDecorator({ keywords: JAVA_KEYWORDS, cStyleComments: true }), ['java']); registerLangHandler(sourceDecorator({ keywords: SH_KEYWORDS, hashComments: true, multiLineStrings: true }), ['bsh', 'csh', 'sh']); registerLangHandler(sourceDecorator({ keywords: PYTHON_KEYWORDS, hashComments: true, multiLineStrings: true, tripleQuotedStrings: true }), ['cv', 'py']); registerLangHandler(sourceDecorator({ keywords: PERL_KEYWORDS, hashComments: true, multiLineStrings: true, regexLiterals: true }), ['perl', 'pl', 'pm']); registerLangHandler(sourceDecorator({ keywords: RUBY_KEYWORDS, hashComments: true, multiLineStrings: true, regexLiterals: true }), ['rb']); registerLangHandler(sourceDecorator({ keywords: JSCRIPT_KEYWORDS, cStyleComments: true, regexLiterals: true }), ['js']); function prettyPrintOne(sourceCodeHtml, opt_langExtension) { try { var sourceAndExtractedTags = extractTags(sourceCodeHtml); var source = sourceAndExtractedTags.source; var extractedTags = sourceAndExtractedTags.tags; if (!langHandlerRegistry.hasOwnProperty(opt_langExtension)) { opt_langExtension = /^\s*</.test(source) ? 'default-markup' : 'default-code'; } var decorations = langHandlerRegistry[opt_langExtension].call({}, source); return recombineTagsAndDecorations(source, extractedTags, decorations); } catch (e) { if ('console' in window) { console.log(e); console.trace(); } return sourceCodeHtml; } } function prettyPrint(opt_whenDone) { var isIE6 = _pr_isIE6(); var codeSegments = [document.getElementsByTagName('pre'), document.getElementsByTagName('code'), document.getElementsByTagName('xmp')]; var elements = []; for (var i = 0; i < codeSegments.length; ++i) { for (var j = 0; j < codeSegments[i].length; ++j) { elements.push(codeSegments[i][j]); } } codeSegments = null; var k = 0; function doWork() { var endTime = (PR_SHOULD_USE_CONTINUATION ? new Date().getTime() + 250 : Infinity); for (; k < elements.length && new Date().getTime() < endTime; k++) { var cs = elements[k]; if (cs.className && cs.className.indexOf('prettyprint') >= 0) { var langExtension = cs.className.match(/\blang-(\w+)\b/); if (langExtension) { langExtension = langExtension[1]; } var nested = false; for (var p = cs.parentNode; p; p = p.parentNode) { if ((p.tagName === 'pre' || p.tagName === 'code' || p.tagName === 'xmp') && p.className && p.className.indexOf('prettyprint') >= 0) { nested = true; break; } } if (!nested) { var content = getInnerHtml(cs); content = content.replace(/(?:\r\n?|\n)$/, ''); var newContent = prettyPrintOne(content, langExtension); if (!isRawContent(cs)) { cs.innerHTML = newContent; } else { var pre = document.createElement('PRE'); for (var i = 0; i < cs.attributes.length; ++i) { var a = cs.attributes[i]; if (a.specified) { var aname = a.name.toLowerCase(); if (aname === 'class') { pre.className = a.value; } else { pre.setAttribute(a.name, a.value); } } } pre.innerHTML = newContent; cs.parentNode.replaceChild(pre, cs); cs = pre; } if (isIE6 && cs.tagName === 'PRE') { var lineBreaks = cs.getElementsByTagName('br'); for (var j = lineBreaks.length; --j >= 0; ) { var lineBreak = lineBreaks[j]; lineBreak.parentNode.replaceChild(document.createTextNode('\r\n'), lineBreak); } } } } } if (k < elements.length) { setTimeout(doWork, 250); } else if (opt_whenDone) { opt_whenDone(); } } doWork(); } window['PR_normalizedHtml'] = normalizedHtml; window['prettyPrintOne'] = prettyPrintOne; window['prettyPrint'] = prettyPrint; window['PR'] = { 'createSimpleLexer': createSimpleLexer, 'registerLangHandler': registerLangHandler, 'sourceDecorator': sourceDecorator, 'PR_ATTRIB_NAME': PR_ATTRIB_NAME, 'PR_ATTRIB_VALUE': PR_ATTRIB_VALUE, 'PR_COMMENT': PR_COMMENT, 'PR_DECLARATION': PR_DECLARATION, 'PR_KEYWORD': PR_KEYWORD, 'PR_LITERAL': PR_LITERAL, 'PR_NOCODE': PR_NOCODE, 'PR_PLAIN': PR_PLAIN, 'PR_PUNCTUATION': PR_PUNCTUATION, 'PR_SOURCE': PR_SOURCE, 'PR_STRING': PR_STRING, 'PR_TAG': PR_TAG, 'PR_TYPE': PR_TYPE }; })();
